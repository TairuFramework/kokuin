import type { Adapter } from '@hozon/adapter'
import type * as Hozon from '@hozon/db'
import {
  HozonDB,
  type Kysely,
  type StoreDefinition,
  sql,
  withKeyLock,
  withKeyLocks,
} from '@hozon/db'
import { getSuite, VAULT_OP_KIND } from '@kokuin/vault'
import { afterAll, afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

import type { EntryRow, KeyAddress, VaultStoreAPI, WrappingRow } from '../src/index.js'
import {
  getVaultRecordsStore,
  getVaultStore,
  vaultRecordsStoreDefinition,
  vaultStoreDefinition,
} from '../src/index.js'

vi.mock('@hozon/db', async (importOriginal) => {
  const actual = await importOriginal<typeof Hozon>()
  return {
    ...actual,
    withKeyLock: vi.fn(actual.withKeyLock),
    withKeyLocks: vi.fn(actual.withKeyLocks),
  }
})

export type StoreHarness = {
  name: string
  createAdapter(): Promise<Adapter>
  cleanup(): Promise<void>
}

export async function openVaultTestDB(harness: StoreHarness, replicated = false) {
  const adapter = await harness.createAdapter()
  const queries: Array<{ sql: string; parameters: ReadonlyArray<unknown> }> = []
  const dialect = adapter.dialect
  const patched = new WeakSet<object>()
  Object.defineProperty(adapter, 'dialect', {
    value: {
      createAdapter: () => dialect.createAdapter(),
      createIntrospector: (raw: Kysely<unknown>) => dialect.createIntrospector(raw),
      createQueryCompiler: () => dialect.createQueryCompiler(),
      createDriver: () => {
        const driver = dialect.createDriver()
        const acquire = driver.acquireConnection.bind(driver)
        driver.acquireConnection = async () => {
          const connection = await acquire()
          if (!patched.has(connection)) {
            patched.add(connection)
            const execute = connection.executeQuery.bind(connection)
            connection.executeQuery = async (query) => {
              queries.push(query)
              return execute(query)
            }
          }
          return connection
        }
        return driver
      },
    },
  })
  const db = new HozonDB({ adapter, tablePrefix: 'vault_cases' })
  db.register(vaultStoreDefinition)
  db.register({
    name: 'rawVault',
    migrations: {},
    createAPI: (db: Kysely<Record<string, never>>) => db,
  } satisfies StoreDefinition<Record<string, never>, Kysely<Record<string, never>>>)
  if (replicated) {
    db.register(vaultRecordsStoreDefinition)
    await getVaultRecordsStore(db, VAULT_OP_KIND)
  }
  return {
    db,
    store: await getVaultStore(db),
    queries,
    kind: adapter.kind,
    raw: await db.getStore<Kysely<Record<string, never>>>('rawVault'),
  }
}

export function stamp(counter: number): string {
  return `2026-10-01T00:00:00.000Z:${counter.toString().padStart(8, '0')}:vault-tests`
}

export function storedEntry(address: KeyAddress, overrides: Partial<EntryRow> = {}): EntryRow {
  return {
    ...address,
    entryID: 'entry-one',
    keyVersion: 1,
    hlc: stamp(1),
    provenance: '',
    kind: 'secret',
    label: 'Primary',
    attributes: { project: 'atlas', colour: 'blue' },
    iv: new Uint8Array(12),
    ciphertext: new Uint8Array([0x80, 0xff, 0x00, 0xc3, 0x28]),
    ...overrides,
  }
}

export function storedWrapping(
  address: KeyAddress,
  overrides: Partial<WrappingRow> = {},
): WrappingRow {
  return {
    ...address,
    wrappingID: 'wrap-one',
    keyVersion: 1,
    descriptors: [
      { kind: 'did', params: { epk: 'AAAA' } },
      { kind: 'pin', params: { salt: 'salt', m: 65536, t: 3, p: 1 } },
    ],
    descriptorDigest: 'opaque-digest',
    iv: new Uint8Array([0x80, 0xff, 0]),
    wrappedKey: new Uint8Array([0xff, 0xc3, 0x28, 0]),
    recipientDID: null,
    provenance: 'unparsed:{not-json}/雪',
    ...overrides,
  }
}

async function expectWriterBlocked(
  db: HozonDB,
  held: KeyAddress,
  write: (store: VaultStoreAPI) => Promise<unknown>,
  addresses: Array<KeyAddress>,
): Promise<void> {
  const actual = await vi.importActual<typeof Hozon>('@hozon/db')
  await db.withTransaction(async (provider) => {
    const store = await getVaultStore(provider)
    const entered = Promise.withResolvers<void>()
    const release = Promise.withResolvers<void>()
    // Use the real shared lock, on a sibling provider rather than its reentrant callback provider.
    const holder = actual.withKeyLock(
      provider,
      'vault_keys',
      [JSON.stringify([held.ownerDID, held.keyID])],
      async () => {
        entered.resolve()
        await release.promise
      },
    )
    await entered.promise
    vi.mocked(withKeyLock).mockClear()
    vi.mocked(withKeyLocks).mockClear()
    let settled = false
    const writer = write(store).finally(() => {
      settled = true
    })
    // Observe failures immediately, but propagate them after releasing the holder.
    void writer.catch(() => {})
    try {
      await new Promise((resolve) => setTimeout(resolve, 40))
      expect(settled, 'writer must wait until the shared key lock is released').toBe(false)
      const tuples = addresses.map((key) => [JSON.stringify([key.ownerDID, key.keyID])])
      if (addresses.length === 1) {
        expect(withKeyLock).toHaveBeenCalledExactlyOnceWith(
          provider,
          'vault_keys',
          tuples[0],
          expect.any(Function),
        )
        expect(withKeyLocks).not.toHaveBeenCalled()
      } else {
        expect(withKeyLocks).toHaveBeenCalledExactlyOnceWith(
          provider,
          'vault_keys',
          tuples,
          expect.any(Function),
        )
        expect(withKeyLock).not.toHaveBeenCalled()
      }
    } finally {
      release.resolve()
      await Promise.all([holder, writer])
    }
    expect(settled).toBe(true)
  })
}

export function storeVaultCases(harness: StoreHarness): void {
  describe(`vault store (${harness.name})`, () => {
    let db: HozonDB
    let store: VaultStoreAPI
    let queries: Array<{ sql: string; parameters: ReadonlyArray<unknown> }>
    let kind: Adapter['kind']
    let address: KeyAddress
    beforeEach(async () => {
      ;({ db, store, queries, kind } = await openVaultTestDB(harness))
      address = { ownerDID: 'did:key:owner', keyID: 'local-key' }
      await store.putKey({ ...address, suite: 1, version: 1, state: 'active' })
    })
    afterEach(async () => {
      try {
        expect(queries.every((query) => query.parameters.length <= 500)).toBe(true)
      } finally {
        await db?.close()
      }
    })
    afterAll(async () => {
      await harness.cleanup()
    })

    test('base schema has only local rows, indexed public metadata and one migration', async () => {
      const rawDefinition: StoreDefinition<unknown, Kysely<unknown>> = {
        name: 'raw',
        migrations: {},
        createAPI: (raw) => raw,
      }
      db.register(rawDefinition)
      const raw = await db.getStore<Kysely<unknown>>('raw')
      const tables = await raw.introspection.getTables()
      const names = tables.map((table) => table.name)
      for (const name of ['vault_keys', 'vault_wrappings', 'vault_entries']) {
        expect(names).toContain(`vault_cases_${name}`)
      }
      expect(
        names
          .filter((name) => name.startsWith('vault_cases_vault_') && !name.includes('_migration'))
          .sort(),
      ).toEqual([
        'vault_cases_vault_entries',
        'vault_cases_vault_keys',
        'vault_cases_vault_wrappings',
      ])
      const modes = await sql<{
        mode: string
      }>`select mode from ${sql.table('vault_keys')}`.execute(raw)
      expect(modes.rows).toEqual([{ mode: 'local' }])
      const migrations = await sql<{
        name: string
      }>`select name from ${sql.table('vault_migration')}`.execute(raw)
      expect(migrations.rows).toEqual([{ name: '0-init' }])
      const indices =
        kind === 'sqlite'
          ? await sql<{
              name: string
            }>`select name from sqlite_master where type = 'index' and tbl_name = 'vault_cases_vault_entries'`.execute(
              raw,
            )
          : await sql<{
              name: string
            }>`select indexname as name from pg_indexes where tablename = 'vault_cases_vault_entries' and schemaname = current_schema()`.execute(
              raw,
            )
      expect(indices.rows.map((row) => row.name)).toEqual(
        expect.arrayContaining([
          'vault_cases_vault_entries_kind_idx',
          'vault_cases_vault_entries_label_idx',
          'vault_cases_vault_entries_id_idx',
          'vault_cases_vault_entries_hlc_idx',
        ]),
      )
      if (kind === 'postgres') {
        expect(indices.rows.map((row) => row.name)).toContain(
          'vault_cases_vault_entries_attributes_idx',
        )
        const collation = await sql<{
          collation_name: string
        }>`select collation_name from information_schema.columns where table_schema = current_schema() and table_name = 'vault_cases_vault_entries' and column_name = 'hlc'`.execute(
          raw,
        )
        expect(collation.rows).toEqual([{ collation_name: 'C' }])
      }
    })

    test('lists and combines public metadata filters without decrypting', async () => {
      const suite = getSuite(1)
      const decrypt = vi.spyOn(suite, 'decryptEntry').mockImplementation(() => {
        throw new Error('metadata queries must not decrypt')
      })
      try {
        await store.putEntry(storedEntry(address))
        await store.putEntry(
          storedEntry(address, {
            entryID: 'entry-two',
            kind: 'blob',
            label: 'Secondary',
            attributes: { project: 'atlas' },
          }),
        )
        await store.putEntry(
          storedEntry(address, {
            entryID: 'entry-three',
            label: 'Primary',
            attributes: { project: 'other' },
          }),
        )
        expect((await store.listEntries(address)).map((row) => row.entryID).sort()).toEqual([
          'entry-one',
          'entry-three',
          'entry-two',
        ])
        expect(
          (await store.listEntries({ ...address, kind: 'blob' })).map((row) => row.entryID),
        ).toEqual(['entry-two'])
        expect(
          (await store.listEntries({ ...address, label: 'Primary' }))
            .map((row) => row.entryID)
            .sort(),
        ).toEqual(['entry-one', 'entry-three'])
        const filtered = await store.listEntries({
          ...address,
          kind: 'secret',
          label: 'Primary',
          attributes: { project: 'atlas' },
        })
        expect(filtered).toEqual([storedEntry(address)])
        expect(await store.listEntries({ ...address, attributes: { absent: 'value' } })).toEqual([])
        expect(decrypt).not.toHaveBeenCalled()
      } finally {
        decrypt.mockRestore()
      }
    })

    test('round-trips opaque provenance and binary bytes without interpretation', async () => {
      const provenance = 'unparsed:{not-json}/a:b\u96ea'
      const row = storedEntry(address, { provenance })
      await store.putEntry(row)
      expect(await store.getEntry(row)).toEqual(row)
      expect((await store.listEntries(address))[0]?.provenance).toBe(provenance)
    })

    test('local keys accept equal versions and refuse lower versions', async () => {
      await store.putKey({ ...address, suite: 1, version: 3, state: 'retired' })
      await store.putKey({ ...address, suite: 1, version: 2, state: 'active' })
      expect(await store.getKey(address)).toMatchObject({ version: 3, state: 'retired' })
      await store.putKey({ ...address, suite: 1, version: 3, state: 'active' })
      expect(await store.getKey(address)).toMatchObject({ version: 3, state: 'active' })
    })

    test.each(['existing', 'absent'] as const)(
      'same-transaction writes share a key lock and cannot overlap its critical section (%s)',
      async (state) => {
        if (state === 'absent') address = { ...address, keyID: 'initially-absent' }
        const actual = await vi.importActual<typeof Hozon>('@hozon/db')
        const lock = vi.mocked(withKeyLock)
        const entered = Promise.withResolvers<void>()
        const release = Promise.withResolvers<void>()
        let active = 0
        let maximum = 0
        let count = 0
        lock.mockClear()
        lock.mockImplementation(async (provider, table, keys, fn) => {
          return await actual.withKeyLock(provider, table, keys, async (tx) => {
            active += 1
            maximum = Math.max(maximum, active)
            count += 1
            try {
              if (count === 1) {
                entered.resolve()
                await release.promise
              }
              return await fn(tx)
            } finally {
              active -= 1
            }
          })
        })
        try {
          await store.transaction(async (tx) => {
            const first = tx.putKey({ ...address, suite: 1, version: 2, state: 'active' })
            // A missing lock must fail promptly instead of leaving the fixture waiting forever.
            await Promise.race([
              entered.promise,
              first.then(() => {
                throw new Error('write completed without acquiring the key lock')
              }),
            ])
            const second = tx.putKey({ ...address, suite: 1, version: 3, state: 'retired' })
            release.resolve()
            await Promise.all([first, second])
            expect(await tx.getKey(address)).toMatchObject({ version: 3, state: 'retired' })
          })
          expect(count).toBe(2)
          expect(maximum).toBe(1)
          const [first, second] = lock.mock.calls
          expect(first?.[0]).toBe(second?.[0])
          expect(first?.slice(1, 3)).toEqual(second?.slice(1, 3))
          expect(first?.slice(1, 3)).toEqual([
            'vault_keys',
            [JSON.stringify([address.ownerDID, address.keyID])],
          ])
        } finally {
          release.resolve()
          lock.mockImplementation(actual.withKeyLock)
        }
      },
    )

    test.each([
      'putKey',
      'setKeyState',
      'setKeyVersion',
      'deleteKey',
      'putWrapping',
      'putWrappings',
      'deleteWrapping',
      'deleteWrappings',
      'deleteWrappingsBelowVersion',
      'putEntry',
      'putEntries',
      'updateEntryIfPresent',
      'updateEntryIfUnchanged',
      'deleteEntry',
      'deleteEntries',
    ] as const)('%s waits for the shared owner-qualified key lock', async (method) => {
      const entry = storedEntry(address)
      const next = { ...entry, hlc: stamp(2), ciphertext: new Uint8Array([42]) }
      const wrapping = storedWrapping(address)
      await store.putEntry(entry)
      await store.putWrapping(wrapping)
      const writers = {
        putKey: (tx: VaultStoreAPI) =>
          tx.putKey({ ...address, suite: 1, version: 2, state: 'retired' }),
        setKeyState: (tx: VaultStoreAPI) => tx.setKeyState({ ...address, state: 'retired' }),
        setKeyVersion: (tx: VaultStoreAPI) => tx.setKeyVersion({ ...address, version: 2 }),
        deleteKey: (tx: VaultStoreAPI) => tx.deleteKey(address),
        putWrapping: (tx: VaultStoreAPI) => tx.putWrapping({ ...wrapping, keyVersion: 2 }),
        putWrappings: (tx: VaultStoreAPI) => tx.putWrappings([{ ...wrapping, keyVersion: 2 }]),
        // Discovery must derive the held key from the row, not from an extra argument field.
        deleteWrapping: (tx: VaultStoreAPI) =>
          tx.deleteWrapping({ ownerDID: address.ownerDID, wrappingID: wrapping.wrappingID }),
        deleteWrappings: (tx: VaultStoreAPI) =>
          tx.deleteWrappings([{ ownerDID: address.ownerDID, wrappingID: wrapping.wrappingID }]),
        deleteWrappingsBelowVersion: (tx: VaultStoreAPI) =>
          tx.deleteWrappingsBelowVersion({ ...address, keyVersion: 2 }),
        putEntry: (tx: VaultStoreAPI) => tx.putEntry(next),
        putEntries: (tx: VaultStoreAPI) => tx.putEntries([next]),
        updateEntryIfPresent: (tx: VaultStoreAPI) => tx.updateEntryIfPresent(next),
        updateEntryIfUnchanged: (tx: VaultStoreAPI) =>
          tx.updateEntryIfUnchanged({ ...next, expectedHLC: entry.hlc }),
        deleteEntry: (tx: VaultStoreAPI) =>
          tx.deleteEntry({ ownerDID: address.ownerDID, entryID: entry.entryID }),
        deleteEntries: (tx: VaultStoreAPI) =>
          tx.deleteEntries([{ ownerDID: address.ownerDID, entryID: entry.entryID }]),
      }
      await expectWriterBlocked(db, address, writers[method], [address])
      switch (method) {
        case 'putKey':
          expect(await store.getKey(address)).toMatchObject({ version: 2, state: 'retired' })
          break
        case 'setKeyState':
          expect(await store.getKey(address)).toMatchObject({ state: 'retired' })
          break
        case 'setKeyVersion':
          expect(await store.getKey(address)).toMatchObject({ version: 2 })
          break
        case 'deleteKey':
          expect(await store.getKey(address)).toBeUndefined()
          break
        case 'putWrapping':
        case 'putWrappings':
          expect(await store.getWrapping(wrapping)).toEqual({ ...wrapping, keyVersion: 2 })
          break
        case 'deleteWrapping':
        case 'deleteWrappings':
        case 'deleteWrappingsBelowVersion':
          expect(await store.getWrapping(wrapping)).toBeUndefined()
          break
        case 'deleteEntry':
        case 'deleteEntries':
          expect(await store.getEntry(entry)).toBeUndefined()
          break
        default:
          expect(await store.getEntry(entry)).toEqual(next)
      }
    })

    test.each(['source', 'target'] as const)(
      'moveEntry waits for the %s key and requests both owner-qualified locks together',
      async (held) => {
        const entry = storedEntry(address)
        const target = { ...address, keyID: 'target-key' }
        const moved = { ...entry, ...target, hlc: stamp(2), ciphertext: new Uint8Array([42]) }
        await store.putEntry(entry)
        await store.putKey({ ...target, suite: 1, version: 1, state: 'active' })
        await expectWriterBlocked(
          db,
          held === 'source' ? address : target,
          (tx) => tx.moveEntry(moved),
          [address, target],
        )
        expect(await store.getEntry(entry)).toEqual(moved)
        expect(await store.listEntries(address)).toEqual([])
      },
    )

    test('vault writes roll back with their enclosing host transaction', async () => {
      const entry = storedEntry(address)
      await expect(
        db.withTransaction(async (host) => {
          const vault = await getVaultStore(host)
          await vault.transaction(async (joined) => {
            await joined.putEntry(entry)
          })
          throw new Error('host journal failed')
        }),
      ).rejects.toThrow('host journal failed')
      expect(await store.getEntry(entry)).toBeUndefined()
    })

    test('generic reads have no persistence effects', async () => {
      const row = storedEntry(address)
      await store.putEntry(row)
      await store.putWrapping(storedWrapping(address))
      const mutations = [
        'putKey',
        'putWrapping',
        'putEntry',
        'moveEntry',
        'updateEntryIfUnchanged',
        'deleteEntry',
      ] as const
      const spies = mutations.map((method) => vi.spyOn(store, method))
      try {
        const before = queries.length
        await store.getKey(address)
        await store.listKeys(address.ownerDID)
        await store.getWrapping({ ...address, wrappingID: 'wrap-one' })
        await store.listWrappings(address)
        expect(await store.getEntry(row)).toEqual(row)
        expect(await store.listEntries(address)).toEqual([row])
        for (const spy of spies) expect(spy).not.toHaveBeenCalled()
        expect(
          queries.slice(before).every((query) => /^(select|begin|commit)/i.test(query.sql)),
        ).toBe(true)
      } finally {
        for (const spy of spies) spy.mockRestore()
      }
    })

    test('moveEntry preserves identity and stores caller-reencrypted target bytes', async () => {
      const source = storedEntry(address)
      await store.putEntry(source)
      const target = { ...address, keyID: 'target-key' }
      await store.putKey({ ...target, suite: 1, version: 1, state: 'active' })
      const moved = { ...source, ...target, ciphertext: new Uint8Array([7, 8, 9]), hlc: stamp(2) }
      await expect(store.putEntry(moved)).rejects.toThrow()
      await store.moveEntry(moved)
      expect(await store.getEntry(source)).toEqual(moved)
      expect(await store.listEntries(address)).toEqual([])
      expect(await store.listEntries(target)).toEqual([moved])
    })

    test('HLC CAS updates exactly the observed row and never inserts or moves', async () => {
      const original = storedEntry(address)
      await store.putEntry(original)
      const next = { ...original, hlc: stamp(2), ciphertext: new Uint8Array([2]) }
      expect(await store.updateEntryIfUnchanged({ ...next, expectedHLC: original.hlc })).toBe(
        'updated',
      )
      expect(
        await store.updateEntryIfUnchanged({
          ...original,
          hlc: stamp(3),
          expectedHLC: original.hlc,
        }),
      ).toBe('superseded')
      expect(await store.getEntry(original)).toEqual(next)
      expect(
        await store.updateEntryIfUnchanged({
          ...next,
          keyID: 'another-key',
          expectedHLC: next.hlc,
        }),
      ).toBe('absent')
      await store.deleteEntry(original)
      expect(await store.updateEntryIfUnchanged({ ...next, expectedHLC: next.hlc })).toBe('absent')
      expect(await store.getEntry(original)).toBeUndefined()
    })

    test('two concurrent HLC CAS attempts have exactly one winner', async () => {
      const original = storedEntry(address)
      await store.putEntry(original)
      const results = await store.transaction(
        async (tx) =>
          await Promise.all([
            tx.updateEntryIfUnchanged({ ...original, hlc: stamp(2), expectedHLC: original.hlc }),
            tx.updateEntryIfUnchanged({ ...original, hlc: stamp(3), expectedHLC: original.hlc }),
          ]),
      )
      expect(results.sort()).toEqual(['superseded', 'updated'])
      const winner = await store.getEntry(original)
      expect([stamp(2), stamp(3)]).toContain(winner?.hlc)
    })

    test('keys are owner-qualified, setters never insert and versions cannot regress', async () => {
      const other = { ...address, ownerDID: 'did:key:other' }
      await store.putKey({ ...other, suite: 1, version: 8, state: 'active' })
      await store.setKeyVersion({ ...address, version: 3 })
      await store.setKeyVersion({ ...address, version: 2 })
      await store.setKeyState({ ...address, state: 'retired' })
      expect(await store.getKey(address)).toEqual({
        ...address,
        suite: 1,
        version: 3,
        state: 'retired',
      })
      expect(await store.listKeys(other.ownerDID)).toEqual([
        { ...other, suite: 1, version: 8, state: 'active' },
      ])
      await store.deleteKey(address)
      await store.setKeyState({ ...address, state: 'active' })
      await store.setKeyVersion({ ...address, version: 4 })
      expect(await store.getKey(address)).toBeUndefined()
      expect(await store.getKey(other)).toBeDefined()
    })

    test('wrapping bytes, ordered descriptors, digest, recipient and provenance round-trip', async () => {
      const row = storedWrapping(address, { recipientDID: 'did:peer:4short:long' })
      await store.putWrapping(row)
      expect(await store.getWrapping(row)).toEqual(row)
      await store.putWrapping({ ...row, keyVersion: 2, recipientDID: null })
      expect(await store.listWrappings({ ...address, keyVersion: 1 })).toEqual([])
      expect(await store.listWrappings({ ...address, keyVersion: 2 })).toEqual([
        { ...row, keyVersion: 2, recipientDID: null },
      ])
      await expect(store.putWrapping({ ...row, keyID: 'other-key' })).rejects.toThrow()
      const other = { ...row, ownerDID: 'did:key:other' }
      await store.putWrapping(other)
      await store.deleteWrapping(row)
      expect(await store.getWrapping(row)).toBeUndefined()
      expect(await store.getWrapping(other)).toEqual(other)
      await store.deleteWrapping(row)
    })

    test('wrapping cleanup removes only older versions for the addressed owner and key', async () => {
      for (const keyVersion of [1, 2, 3]) {
        await store.putWrapping(
          storedWrapping(address, { wrappingID: `wrap-${keyVersion}`, keyVersion }),
        )
      }
      const other = storedWrapping({ ...address, ownerDID: 'did:key:other' })
      await store.putWrapping(other)
      await store.deleteWrappingsBelowVersion({ ...address, keyVersion: 3 })
      expect((await store.listWrappings(address)).map((row) => row.keyVersion)).toEqual([3])
      expect(await store.getWrapping(other)).toEqual(other)
    })

    test('entry replacement, owner isolation, conditional update and maximum HLC', async () => {
      expect(await store.getMaxEntryHLC()).toBeNull()
      const row = storedEntry(address)
      expect(await store.updateEntryIfPresent(row)).toBe('absent')
      await store.moveEntry(row)
      expect(await store.getEntry(row)).toBeUndefined()
      await store.putEntry(row)
      const other = { ...row, ownerDID: 'did:key:other', hlc: stamp(9) }
      await store.putEntry(other)
      expect(await store.listEntryOwners(row.entryID)).toEqual(
        ['did:key:other', address.ownerDID].sort(),
      )
      const next = { ...row, hlc: stamp(2), ciphertext: new Uint8Array(32), attributes: {} }
      expect(await store.updateEntryIfPresent({ ...next, keyID: 'wrong' })).toBe('absent')
      expect(await store.updateEntryIfPresent(next)).toBe('updated')
      expect(await store.getEntry(row)).toEqual(next)
      expect(await store.getEntryWithProvenance(row)).toEqual(next)
      expect(await store.getMaxEntryHLC()).toBe(other.hlc)
      await store.putEntry(row)
      expect(await store.getEntry(row)).toEqual(row)
      await store.deleteEntry(row)
      await store.deleteEntry(row)
      expect(await store.getEntry(other)).toEqual(other)
    })

    test('batched writes match per-row writes across statement chunks', async () => {
      const count = 250
      const entries = Array.from({ length: count }, (_, i) => {
        return storedEntry(address, {
          entryID: `entry-${String(i).padStart(3, '0')}`,
          hlc: stamp(i),
        })
      })
      const wrappings = Array.from({ length: count }, (_, i) => {
        return storedWrapping(address, { wrappingID: `wrap-${String(i).padStart(3, '0')}` })
      })
      const before = queries.length
      await store.putEntries(entries)
      await store.putWrappings(wrappings)
      // Rows are bound in chunks under the parameter budget, not one statement per row.
      expect(queries.length - before).toBeLessThan(40)
      expect(await store.listEntries(address)).toEqual(entries)
      expect(await store.listWrappings(address)).toEqual(wrappings)

      // A later row for one address wins, as a later sequential write would.
      const first = entries[0] as EntryRow
      const replaced = { ...first, hlc: stamp(900), ciphertext: new Uint8Array([9]) }
      await store.putEntries([{ ...first, hlc: stamp(899) }, replaced])
      expect(await store.getEntry(first)).toEqual(replaced)

      // A row held by another key refuses the whole batch, as the single write refuses its row.
      const fresh = storedEntry(address, { entryID: 'entry-fresh' })
      await expect(store.putEntries([fresh, { ...replaced, keyID: 'other-key' }])).rejects.toThrow(
        'Entry belongs to another key',
      )
      expect(await store.getEntry(fresh)).toBeUndefined()
      await expect(store.putEntries([fresh, { ...fresh, keyID: 'other-key' }])).rejects.toThrow(
        'Entry belongs to another key',
      )
      await expect(
        store.putWrappings([{ ...(wrappings[0] as WrappingRow), keyID: 'other-key' }]),
      ).rejects.toThrow('Wrapping belongs to another key')

      const deleting = queries.length
      await store.deleteEntries([
        ...entries.map((row) => ({ ownerDID: row.ownerDID, entryID: row.entryID })),
        { ownerDID: address.ownerDID, entryID: 'entry-missing' },
      ])
      await store.deleteWrappings(wrappings)
      expect(queries.length - deleting).toBeLessThan(40)
      expect(await store.listEntries(address)).toEqual([])
      expect(await store.listWrappings(address)).toEqual([])
      await store.deleteEntries([])
      await store.putEntries([])
    })

    test('attribute subsets require own exact string values and combine without a bind limit', async () => {
      const row = storedEntry(address, { attributes: { project: 'atlas', "a.b'[]": '雪' } })
      await store.putEntry(row)
      expect(await store.listEntries({ ...address, label: 'primary' })).toEqual([])
      expect(await store.listEntries({ ...address, attributes: { toString: 'value' } })).toEqual([])
      expect(await store.listEntries({ ...address, attributes: { "a.b'[]": '雪' } })).toEqual([row])
      const attributes = Object.fromEntries(
        Array.from({ length: 600 }, (_, i) => [`field-${i}`, `${i}`]),
      )
      const large = { ...row, attributes }
      await store.putEntry(large)
      expect(await store.listEntries({ ...address, attributes })).toEqual([large])
    })

    test('explicit key locks require a transaction and accept large duplicate sets', async () => {
      await expect(store.lockKeyRow(address)).rejects.toThrow('transaction')
      await expect(store.lockKeyRows([])).rejects.toThrow('transaction')
      await store.transaction(async (tx) => {
        expect(tx.isTransaction).toBe(true)
        await tx.lockKeyRows([])
        await tx.lockKeyRows(
          Array.from({ length: 510 }, (_, i) => ({ ...address, keyID: `key-${i}` })),
        )
        await tx.lockKeyRows([address, address])
        await tx.lockKeyRow(address)
        await tx.putKey({ ...address, suite: 1, version: 2, state: 'active' })
      })
      expect((await store.getKey(address))?.version).toBe(2)
    })

    test.each(['deleted', 'moved'] as const)(
      'move does not overwrite a source that was %s before locking',
      async (change) => {
        const source = storedEntry(address)
        await store.putEntry(source)
        const survivor = { ...source, keyID: 'surviving-key', ciphertext: new Uint8Array([99]) }
        const actual = await vi.importActual<typeof Hozon>('@hozon/db')
        const locks = vi.mocked(withKeyLocks)
        locks.mockImplementationOnce(async (provider, table, keys, fn) => {
          if (change === 'deleted') await store.deleteEntry(source)
          else await store.moveEntry(survivor)
          return actual.withKeyLocks(provider, table, keys, fn)
        })
        try {
          await store.moveEntry({ ...source, keyID: 'stale-target' })
          expect(await store.getEntry(source)).toEqual(change === 'deleted' ? undefined : survivor)
        } finally {
          locks.mockImplementation(actual.withKeyLocks)
        }
      },
    )

    test('delete preserves an entry reassociated after source discovery', async () => {
      const source = storedEntry(address)
      await store.putEntry(source)
      const survivor = { ...source, keyID: 'surviving-key', ciphertext: new Uint8Array([99]) }
      const actual = await vi.importActual<typeof Hozon>('@hozon/db')
      const lock = vi.mocked(withKeyLock)
      lock.mockImplementationOnce(async (provider, table, keys, fn) => {
        await store.moveEntry(survivor)
        return actual.withKeyLock(provider, table, keys, fn)
      })
      try {
        await store.deleteEntry(source)
        expect(await store.getEntry(source)).toEqual(survivor)
      } finally {
        lock.mockImplementation(actual.withKeyLock)
      }
    })
  })
}
