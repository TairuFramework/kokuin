import { HozonDB, sql } from '@hozon/db'
import { controllerStoreDefinition, getControllerStore } from '@kokuin/store-controller'
import { delegationStoreDefinition, getDelegationStore } from '@kokuin/store-delegation'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'

import { controllerStoreCases } from '../../../packages/store-controller/test/cases.js'
import { delegationStoreCases, indexNames } from '../../../packages/store-delegation/test/cases.js'
import { type Backend, backends } from '../src/backends.js'
import { type RawDB, rawStore } from '../src/helpers.js'

// Databases written by an earlier in-application implementation use a custom prefix.
const PREFIX = 'legacy'

function harness(b: Backend) {
  return { name: b.name, createAdapter: () => b.createAdapter(), cleanup: () => b.cleanup() }
}

async function tableNames(raw: RawDB, kind: 'sqlite' | 'postgres'): Promise<Array<string>> {
  const query =
    kind === 'sqlite'
      ? sql<{ name: string }>`select name from sqlite_master where type = 'table'`
      : sql<{ name: string }>`select table_name as name from information_schema.tables
        where table_schema = current_schema()`
  const { rows } = await query.execute(raw)
  return rows.map((row) => row.name)
}

describe.each(backends())('$name', (b) => {
  let db: HozonDB
  let raw: RawDB

  beforeAll(async () => {
    db = new HozonDB({ adapter: await b.createAdapter(), tablePrefix: PREFIX })
    db.register(controllerStoreDefinition)
    db.register(delegationStoreDefinition)
    db.register(rawStore)
    await getControllerStore(db)
    await getDelegationStore(db)
    raw = await db.getStore<RawDB>('raw')
  }, 120_000)

  afterAll(async () => {
    await db?.close()
    await b.cleanup()
  })

  test('store and migration tables carry the prefix', async () => {
    expect(await tableNames(raw, db.adapter.kind)).toEqual(
      expect.arrayContaining([
        'legacy_controller_logs',
        'legacy_delegation_tokens',
        'legacy_revoked_capabilities',
        'legacy_controller_migration',
        'legacy_delegation_migration',
      ]),
    )
  })

  test('secondary indexes carry the prefix', async () => {
    expect(await indexNames(raw, db.adapter.kind, 'legacy_delegation_tokens')).toEqual(
      expect.arrayContaining([
        'legacy_delegation_tokens_grantor_audience_idx',
        'legacy_delegation_tokens_audience_exp_idx',
        'legacy_delegation_tokens_jti_idx',
      ]),
    )
    expect(await indexNames(raw, db.adapter.kind, 'legacy_revoked_capabilities')).toContain(
      'legacy_revoked_capabilities_verified_cap_exp_idx',
    )
  })

  // Postgres names the constraint in its catalog. SQLite keeps no constraint catalog, and its
  // primary-key index is an unnamed `sqlite_autoindex_*`, so only the stored DDL holds the name.
  test('primary keys carry the prefix', async () => {
    const expected = [
      ['legacy_controller_logs', 'legacy_controller_logs_pkey'],
      ['legacy_delegation_tokens', 'legacy_delegation_tokens_pkey'],
      ['legacy_revoked_capabilities', 'legacy_revoked_capabilities_pkey'],
    ]
    if (db.adapter.kind === 'postgres') {
      const { rows } = await sql<{ table: string; name: string }>`
        select table_name as table, constraint_name as name
        from information_schema.table_constraints
        where table_schema = current_schema() and constraint_type = 'PRIMARY KEY'
          and table_name like 'legacy\\_%'
        order by table_name`.execute(raw)
      expect(rows.map((row) => [row.table, row.name])).toEqual(expect.arrayContaining(expected))
    } else {
      for (const [table, name] of expected) {
        const { rows } = await sql<{ ddl: string }>`
          select sql as ddl from sqlite_master
          where type = 'table' and name = ${sql.lit(table)}`.execute(raw)
        expect(rows[0]?.ddl).toMatch(new RegExp(`constraint\\s+"${name}"\\s+primary key`, 'i'))
      }
    }
  })

  test.runIf(b.name === 'postgres')('hlc columns use the C collation', async () => {
    const { rows } = await sql<{ table: string; collation: string | null }>`
      select table_name as table, collation_name as collation
      from information_schema.columns
      where table_schema = current_schema() and column_name = 'hlc'
      order by table_name`.execute(raw)
    expect(rows).toEqual([
      { table: 'legacy_delegation_tokens', collation: 'C' },
      { table: 'legacy_revoked_capabilities', collation: 'C' },
    ])
  })
})

describe.each(backends())('$name controller cases under the legacy prefix', (b) => {
  describe('controller', () => controllerStoreCases(harness(b), { tablePrefix: PREFIX }))
})

describe.each(backends())('$name delegation cases under the legacy prefix', (b) => {
  describe('delegation', () => delegationStoreCases(harness(b), { tablePrefix: PREFIX }))
})
