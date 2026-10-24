import type { Dialect } from 'kysely'
import {
  DummyDriver,
  Kysely,
  PostgresAdapter,
  PostgresIntrospector,
  PostgresQueryCompiler,
  SqliteAdapter,
  SqliteIntrospector,
  SqliteQueryCompiler,
} from 'kysely'
import { describe, expect, test } from 'vitest'

import type { EntryValues, WrappingValues } from '../src/batch.js'
import {
  DECISION_COLUMNS,
  deleteEntryRows,
  deleteWrappingRows,
  ENTRY_COLUMNS,
  insertDecisionClaims,
  KEY_BRANCH_COLUMNS,
  PARAMETER_BUDGET,
  selectDecisionModes,
  selectEntries,
  statementChunks,
  upsertEntries,
  upsertKeyBranches,
  upsertReplicatedDecision,
  upsertWrappings,
  WRAPPING_COLUMNS,
} from '../src/batch.js'
import type { VaultRecordsTables } from '../src/record-tables.js'

// Compile-only: no driver connects. Postgres runs are the integration suite's.
const dialects: Record<'postgres' | 'sqlite', Dialect> = {
  postgres: {
    createAdapter: () => new PostgresAdapter(),
    createDriver: () => new DummyDriver(),
    createIntrospector: (db) => new PostgresIntrospector(db),
    createQueryCompiler: () => new PostgresQueryCompiler(),
  },
  sqlite: {
    createAdapter: () => new SqliteAdapter(),
    createDriver: () => new DummyDriver(),
    createIntrospector: (db) => new SqliteIntrospector(db),
    createQueryCompiler: () => new SqliteQueryCompiler(),
  },
}

function wrapping(index: number): WrappingValues {
  return {
    owner_did: 'did:key:owner',
    wrapping_id: `wrap-${index}`,
    key_id: 'key',
    key_version: 1,
    descriptors: [],
    descriptor_digest: 'digest',
    iv: new Uint8Array(12),
    wrapped_key: new Uint8Array(32),
    recipient_did: null,
    provenance: 'branch',
  }
}

function entry(index: number): EntryValues {
  return {
    owner_did: 'did:key:owner',
    entry_id: `entry-${index}`,
    key_id: 'key',
    key_version: 1,
    kind: 'secret',
    label: 'label',
    attributes: {},
    iv: new Uint8Array(12),
    ciphertext: new Uint8Array(8),
    hlc: 'hlc',
    provenance: 'branch',
  }
}

describe.each(['postgres', 'sqlite'] as const)('batched vault statements (%s)', (name) => {
  const db = new Kysely<VaultRecordsTables>({ dialect: dialects[name] })

  test('a full chunk of each statement stays within the parameter budget', () => {
    const wrappings = statementChunks(
      Array.from({ length: 300 }, (_, i) => wrapping(i)),
      WRAPPING_COLUMNS,
    )
    const entries = statementChunks(
      Array.from({ length: 300 }, (_, i) => entry(i)),
      ENTRY_COLUMNS,
    )

    expect(wrappings.length).toBeGreaterThan(1)
    expect(entries.length).toBeGreaterThan(1)

    for (const part of wrappings) {
      const compiled = upsertWrappings(db, part).compile()

      expect(compiled.parameters).toHaveLength(part.length * WRAPPING_COLUMNS)
      expect(compiled.parameters.length).toBeLessThanOrEqual(PARAMETER_BUDGET)
    }

    for (const part of entries) {
      const compiled = upsertEntries(db, part).compile()

      expect(compiled.parameters).toHaveLength(part.length * ENTRY_COLUMNS)
      expect(compiled.parameters.length).toBeLessThanOrEqual(PARAMETER_BUDGET)
    }

    const decisions = Array.from({ length: 300 }, (_, i) => {
      return { type: 'vault.entry', owner: 'did:key:owner', id: `entry-${i}` }
    })

    for (const part of statementChunks(decisions, DECISION_COLUMNS)) {
      expect(
        insertDecisionClaims(db, part, 'local').compile().parameters.length,
      ).toBeLessThanOrEqual(PARAMETER_BUDGET)
      expect(selectDecisionModes(db, part).compile().parameters.length).toBeLessThanOrEqual(
        PARAMETER_BUDGET,
      )
    }

    const branches = Array.from({ length: 300 }, (_, i) => {
      return {
        owner_did: 'did:key:owner',
        key_id: 'key',
        key_version: 1,
        record_id: `branch-${i}`,
        branch_id: 'branch',
        op_jwt: 'jwt',
      }
    })

    for (const part of statementChunks(branches, KEY_BRANCH_COLUMNS))
      expect(upsertKeyBranches(db, part).compile().parameters.length).toBeLessThanOrEqual(
        PARAMETER_BUDGET,
      )
  })

  test('multi-row upserts update from the excluded row only while the key matches', () => {
    const { sql } = upsertWrappings(db, [wrapping(0), wrapping(1)]).compile()

    expect(sql).toContain(
      'on conflict ("owner_did", "wrapping_id") do update set "key_id" = "excluded"."key_id"',
    )
    expect(sql).toContain('where "vault_wrappings"."key_id" = "excluded"."key_id"')

    const entries = upsertEntries(db, [entry(0), entry(1)]).compile().sql

    expect(entries).toContain('on conflict ("owner_did", "entry_id") do update set')
    expect(entries).toContain('"hlc" = "excluded"."hlc"')
    expect(entries).toContain('where "vault_entries"."key_id" = "excluded"."key_id"')
  })

  test('the replicated decision claim updates only a replicated row', () => {
    const compiled = upsertReplicatedDecision(db, {
      type: 'vault.entry',
      owner: 'did:key:owner',
      id: 'entry',
      content_digest: 'digest',
      decision_hlc: 'hlc',
    }).compile()

    expect(compiled.sql).toContain('on conflict ("type", "owner", "id") do update set')
    expect(compiled.sql).toContain('where "vault_decisions"."mode" = ')
    expect(compiled.parameters).toContain('replicated')
  })

  test('keyed reads and deletes name each row by its full address', () => {
    const rows = [
      { owner_did: 'did:key:a', entry_id: 'one', key_id: 'key' },
      { owner_did: 'did:key:b', entry_id: 'two', key_id: 'key' },
    ]
    const select = selectEntries(db, rows).compile()
    const remove = deleteEntryRows(db, rows).compile()
    const wrappings = deleteWrappingRows(db, [
      { owner_did: 'did:key:a', wrapping_id: 'one', key_id: 'key' },
    ]).compile()

    expect(select.parameters).toEqual(['did:key:a', 'one', 'did:key:b', 'two'])
    expect(remove.parameters).toEqual(['did:key:a', 'one', 'key', 'did:key:b', 'two', 'key'])
    expect(remove.sql).toContain(' or ')
    expect(wrappings.parameters).toEqual(['did:key:a', 'one', 'key'])
  })
})
