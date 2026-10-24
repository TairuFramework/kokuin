import type { Kysely, StoreDefinition } from '@hozon/db'
import { HozonDB, sql } from '@hozon/db'
import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import type * as Token from '@kokuin/token'
import { randomIdentity } from '@kokuin/token'
import { getSuite, VAULT_OP_KIND } from '@kokuin/vault'
import { createRuntime } from '@sozai/runtime'
import { afterEach, describe, expect, test, vi } from 'vitest'

import type { KeyAddress, VaultCoordinator } from '../src/index.js'
import {
  createVaultCoordinator,
  getVaultRecordsStore,
  getVaultStore,
  vaultRecordsStoreDefinition,
  vaultStoreDefinition,
} from '../src/index.js'

// Counts every token signature verification, the cost the memos below save.
const verifications = vi.hoisted(() => ({ count: 0 }))

vi.mock('@kokuin/token', async (importOriginal) => {
  const actual = await importOriginal<typeof Token>()

  return {
    ...actual,
    verifyToken: new Proxy(actual.verifyToken, {
      apply(target, self, args) {
        verifications.count += 1

        return Reflect.apply(target, self, args)
      },
    }),
  }
})

type Measured = {
  /** Statements executed, including transaction control. */
  total: number
  /** Single-key `vault.entry` record reads. */
  entryGets: number
  /** Batched record reads. */
  batchGets: number
  /** `vault.key-branch` record rows read. */
  branchRows: number
  /** Token signature verifications. */
  verifies: number
  /** Most statements built and not yet finished at once. Above 1 means reads overlapped. */
  peak: number
}

type CorruptRow = { type: string; id: string; error: unknown }

type Fixture = {
  manager: VaultCoordinator
  ownerDID: string
  raw: Kysely<Record<string, never>>
  corruptRows: Array<CorruptRow>
  measure(operation: () => Promise<unknown>): Promise<Measured>
  /** Makes the next HLC allocations wait for `gate`, then reject. */
  failClock(gate: Promise<unknown>): void
}

const bytes = (text: string) => new TextEncoder().encode(text)
const metadata = { kind: 'blob', label: 'State', attributes: { app: 'test' } }
const runtime = createRuntime()

async function fixture(): Promise<Fixture> {
  const adapter = new NodeSQLiteAdapter({ database: ':memory:' })
  const stats: Measured = {
    total: 0,
    entryGets: 0,
    batchGets: 0,
    branchRows: 0,
    verifies: 0,
    peak: 0,
  }
  const corruptRows: Array<CorruptRow> = []
  const tally = async <Result extends { rows: Array<unknown> }>(
    running: Promise<Result>,
    branchRead: boolean,
  ): Promise<Result> => {
    const result = await running

    if (branchRead)
      stats.branchRows += result.rows.filter((row) => {
        return (row as { type?: unknown }).type === 'vault.key-branch'
      }).length

    return result
  }
  // Kysely runs one statement at a time per transaction connection, after building it. Count
  // from build to completion, so overlapping requests are visible despite that queue.
  const pending = new WeakSet<object>()
  let active = 0
  const dialect = adapter.dialect
  const patched = new WeakSet<object>()

  Object.defineProperty(adapter, 'dialect', {
    value: {
      createAdapter: () => dialect.createAdapter(),
      createIntrospector: (raw: Kysely<unknown>) => dialect.createIntrospector(raw),
      createQueryCompiler: () => {
        const compiler = dialect.createQueryCompiler()
        const compile = compiler.compileQuery.bind(compiler)

        compiler.compileQuery = (node, queryID) => {
          const compiled = compile(node, queryID)

          pending.add(compiled)
          active += 1
          stats.peak = Math.max(stats.peak, active)

          return compiled
        }

        return compiler
      },
      createDriver: () => {
        const driver = dialect.createDriver()
        const acquire = driver.acquireConnection.bind(driver)

        driver.acquireConnection = async () => {
          const connection = await acquire()

          if (!patched.has(connection)) {
            patched.add(connection)

            const execute = connection.executeQuery.bind(connection)

            connection.executeQuery = async (query) => {
              stats.total += 1

              const records = /^select \* from "\w+_vault_records" where /.test(query.sql)

              if (records) {
                if (query.sql.includes(' or ')) stats.batchGets += 1
                else if (query.parameters[0] === 'vault.entry') stats.entryGets += 1
              }

              try {
                return await tally(
                  execute(query),
                  records && query.parameters.includes('vault.key-branch'),
                )
              } finally {
                if (pending.delete(query)) active -= 1
              }
            }
          }

          return connection
        }

        return driver
      },
    },
  })

  const db = new HozonDB({ adapter, tablePrefix: 'vault_calls' })

  db.register(vaultStoreDefinition)
  db.register({
    name: 'rawVault',
    migrations: {},
    createAPI: (raw: Kysely<Record<string, never>>) => raw,
  } satisfies StoreDefinition<Record<string, never>, Kysely<Record<string, never>>>)
  db.register(vaultRecordsStoreDefinition)
  await getVaultRecordsStore(db, VAULT_OP_KIND)

  const identity = randomIdentity()
  let counter = 1000
  let clockGate: Promise<unknown> | undefined
  const manager = createVaultCoordinator({
    store: await getVaultStore(db),
    principal: identity.id,
    identity,
    runtime,
    authority: { authorize: async () => true },
    nextHLC: async () => {
      if (clockGate !== undefined) {
        await clockGate

        throw new Error('clock unavailable')
      }

      counter += 1

      return `2026-10-01T00:00:00.000Z:${counter.toString().padStart(8, '0')}:vault-calls`
    },
    mode: 'replicated',
    signer: identity,
    records: {
      opKind: VAULT_OP_KIND,
      nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
      maxDriftMS: 60_000,
      validateConsumerMetadata: async () => true,
      onCorruptRow: (info) => corruptRows.push(info),
    },
  })

  return {
    manager,
    ownerDID: identity.id,
    raw: await db.getStore<Kysely<Record<string, never>>>('rawVault'),
    corruptRows,
    async measure(operation) {
      stats.total = 0
      stats.entryGets = 0
      stats.batchGets = 0
      stats.branchRows = 0
      stats.peak = 0
      verifications.count = 0
      await operation()

      return { ...stats, verifies: verifications.count }
    },
    failClock(gate) {
      clockGate = gate
    },
  }
}

async function keyWithEntries(f: Fixture, count: number): Promise<KeyAddress> {
  const key = await f.manager.createKey({ ownerDID: f.ownerDID })

  for (let index = 0; index < count; index += 1)
    await f.manager.putEntry({
      ...key,
      entryID: `${key.keyID}:${index}`,
      plaintext: bytes(`value ${index}`),
      ...metadata,
    })

  return key
}

describe('coordinator store calls (replicated)', () => {
  test('entry, open and rotate operations batch reads and overlap independent calls', async () => {
    const f = await fixture()
    const key = await keyWithEntries(f, 1)
    const target = await f.manager.createKey({ ownerDID: f.ownerDID })
    const entry = { ownerDID: f.ownerDID, entryID: 'measured' }
    const put = await f.measure(() => {
      return f.manager.putEntry({ ...key, ...entry, plaintext: bytes('one'), ...metadata })
    })
    const update = await f.measure(() => {
      return f.manager.updateEntry({ ...entry, plaintext: bytes('two') })
    })
    const read = await f.measure(() => f.manager.readEntry(entry))

    await f.manager.lock(key)

    const open = await f.measure(() => f.manager.openKey(key))
    const list = await f.measure(() => f.manager.listEntries(key))
    const reKey = await f.measure(() => {
      return f.manager.reKeyEntry({ ...entry, toKeyID: target.keyID })
    })
    const remove = await f.measure(() => f.manager.deleteEntry(entry))
    const small = await keyWithEntries(f, 4)
    const large = await keyWithEntries(f, 12)
    const rotate4 = await f.measure(() => {
      return f.manager.rotate({ ...small, excludedRecipients: [], reissue: [] })
    })
    const rotate12 = await f.measure(() => {
      return f.manager.rotate({ ...large, excludedRecipients: [], reissue: [] })
    })
    const perEntry = {
      total: (rotate12.total - rotate4.total) / 8,
      entryGets: (rotate12.entryGets - rotate4.entryGets) / 8,
      verifies: (rotate12.verifies - rotate4.verifies) / 8,
    }

    console.table({ put, update, read, open, list, reKey, delete: remove, rotate4, rotate12 })
    console.log('rotate cost per additional entry', perEntry)

    // Each new entry record still costs one read: its copy persistence. Entry-info, precondition,
    // read-back and apply decision reads are batched.
    expect(perEntry.entryGets).toBeLessThanOrEqual(1)
    expect(rotate12.batchGets).toBe(rotate4.batchGets)
    expect(rotate12.branchRows).toBe(rotate4.branchRows)
    expect(perEntry.total).toBeLessThanOrEqual(12)

    // Each signed op is verified once per process: a write verifies only the record it signs.
    expect(perEntry.verifies).toBeLessThanOrEqual(1)
    for (const measured of [put, update, reKey, remove])
      expect(measured.verifies).toBeLessThanOrEqual(1)

    // Independent reads inside one transaction are requested together. Reads outside a
    // transaction, as in openKey, each take the single SQLite connection in turn.
    for (const measured of [put, update, reKey, remove, rotate4])
      expect(measured.peak).toBeGreaterThan(1)
  })
})

describe('records apply reads (replicated)', () => {
  const types = [
    'vault.key',
    'vault.key-branch',
    'vault.wrapping',
    'vault.entry',
    'vault.revocation',
  ]

  async function applyCost(count: number): Promise<Measured> {
    const source = await fixture()

    await keyWithEntries(source, count)

    const records = (await source.manager.records.adapter.list(types)).flatMap((d) => d.copies)
    const target = await fixture()
    let applied = 0
    const measured = await target.measure(async () => {
      applied = (await target.manager.records.apply(records)).applied
    })

    expect(applied).toBe(records.length)

    return measured
  }

  test('an incoming chunk batches its decision, dependency and owner reads', async () => {
    const small = await applyCost(4)
    const large = await applyCost(12)
    const perEntry = {
      total: (large.total - small.total) / 8,
      entryGets: (large.entryGets - small.entryGets) / 8,
      branchRows: (large.branchRows - small.branchRows) / 8,
      verifies: (large.verifies - small.verifies) / 8,
    }

    console.table({ apply4: small, apply12: large })
    console.log('apply cost per additional entry', perEntry)

    // Left per entry record: its copy persistence, projection and candidate writes.
    expect(perEntry.entryGets).toBeLessThanOrEqual(1)
    expect(perEntry.branchRows).toBe(0)
    expect(large.batchGets).toBe(small.batchGets)
    expect(perEntry.total).toBeLessThanOrEqual(12)
    // At most one verification per incoming token. These tokens were verified when the source
    // wrote them, in this process, so the shared memo answers them all.
    expect(perEntry.verifies).toBeLessThanOrEqual(1)
  })
})

describe('coordinator secret cleanup on partial failure', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('a sibling rejection after the key opens leaves the opened key zeroed', async () => {
    const f = await fixture()
    const key = await f.manager.createKey({ ownerDID: f.ownerDID })
    const suite = getSuite(1)
    const unwrap = suite.unwrap.bind(suite)
    const opened: Array<Uint8Array> = []
    const unwrapped = Promise.withResolvers<void>()

    vi.spyOn(suite, 'unwrap').mockImplementation(async (params) => {
      const contentKey = await unwrap(params)

      opened.push(contentKey)
      unwrapped.resolve()

      return contentKey
    })
    f.failClock(unwrapped.promise)

    await expect(
      f.manager.putEntry({ ...key, entryID: 'cleanup', plaintext: bytes('secret'), ...metadata }),
    ).rejects.toThrow('clock unavailable')
    expect(opened).toHaveLength(1)
    expect(opened[0]?.some((byte) => byte !== 0)).toBe(false)
  })

  test('a failed target open leaves the decrypted source plaintext zeroed', async () => {
    const f = await fixture()
    const key = await f.manager.createKey({ ownerDID: f.ownerDID })
    const entry = await f.manager.putEntry({
      ...key,
      entryID: 'moving',
      plaintext: bytes('secret'),
      ...metadata,
    })
    const suite = getSuite(1)
    const decryptEntry = suite.decryptEntry.bind(suite)
    const plaintexts: Array<Uint8Array> = []

    vi.spyOn(suite, 'decryptEntry').mockImplementation((params) => {
      const plaintext = decryptEntry(params)

      plaintexts.push(plaintext)

      return plaintext
    })

    // The target key does not exist, so only the target open rejects.
    await expect(f.manager.reKeyEntry({ ...entry, toKeyID: 'missing-key' })).rejects.toMatchObject({
      name: 'VaultNotFound',
    })
    expect(plaintexts).toHaveLength(1)
    expect(plaintexts[0]?.some((byte) => byte !== 0)).toBe(false)
  })
})

describe('key-branch lookup', () => {
  async function branchRecordID(f: Fixture, key: KeyAddress): Promise<string> {
    const { rows } = await sql<{ record_id: string }>`
      select record_id from ${sql.table('vault_key_branches')}
      where owner_did = ${key.ownerDID} and key_id = ${key.keyID}`.execute(f.raw)
    const id = rows[0]?.record_id

    if (id === undefined) throw new Error('missing branch projection')

    return id
  }

  test('a replicated write reads a constant number of branch records', async () => {
    const f = await fixture()
    const key = await keyWithEntries(f, 0)
    const write = (entryID: string) => {
      return f.manager.putEntry({ ...key, entryID, plaintext: bytes(entryID), ...metadata })
    }
    const few = await f.measure(() => write('few'))

    for (let index = 0; index < 10; index += 1) await keyWithEntries(f, 0)

    const many = await f.measure(() => write('many'))

    console.log('key-branch rows per write', { few: few.branchRows, many: many.branchRows })

    // One proof lookup by the coordinator, plus the records apply engine's per-record reads.
    expect(many.branchRows).toBe(few.branchRows)
    expect(many.branchRows).toBeLessThanOrEqual(3)
  })

  test('a missing branch record fails closed', async () => {
    const f = await fixture()
    const key = await keyWithEntries(f, 0)
    const id = await branchRecordID(f, key)

    await sql`delete from ${sql.table('vault_records')}
      where type = 'vault.key-branch' and id = ${id}`.execute(f.raw)
    await f.manager.lock(key)

    await expect(f.manager.openKey(key)).rejects.toMatchObject({ name: 'VaultRepairPending' })
  })

  test('a corrupt branch record fails closed and is reported', async () => {
    const f = await fixture()
    const key = await keyWithEntries(f, 0)
    const id = await branchRecordID(f, key)

    await sql`update ${sql.table('vault_records')} set meta = ${'{"forged":true}'}
      where type = 'vault.key-branch' and id = ${id}`.execute(f.raw)
    await f.manager.lock(key)

    await expect(f.manager.openKey(key)).rejects.toMatchObject({ name: 'VaultRepairPending' })
    expect(f.corruptRows).toContainEqual(expect.objectContaining({ type: 'vault.key-branch', id }))
  })

  test('a projection naming another key-branch record fails closed', async () => {
    const f = await fixture()
    const key = await keyWithEntries(f, 0)
    const other = await keyWithEntries(f, 0)
    const otherID = await branchRecordID(f, other)

    // The projection is unique per record, so first drop the other key's row.
    await sql`delete from ${sql.table('vault_key_branches')}
      where owner_did = ${other.ownerDID} and key_id = ${other.keyID}`.execute(f.raw)
    await sql`update ${sql.table('vault_key_branches')} set record_id = ${otherID}
      where owner_did = ${key.ownerDID} and key_id = ${key.keyID}`.execute(f.raw)
    await f.manager.lock(key)

    await expect(f.manager.openKey(key)).rejects.toMatchObject({ name: 'VaultRepairPending' })
  })
})
