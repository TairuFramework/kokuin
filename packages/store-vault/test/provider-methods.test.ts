import type { StoreProvider } from '@hozon/db'
import { HozonDB } from '@hozon/db'
import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import type { MethodRegistry } from '@kokuin/token'
import { createSigningIdentityForDID, randomIdentity } from '@kokuin/token'
import { VAULT_OP_KIND } from '@kokuin/vault'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createRuntime } from '@sozai/runtime'
import { expect, test } from 'vitest'

import {
  createVaultCoordinator,
  getVaultRecordsStore,
  getVaultStore,
  vaultRecordsStoreDefinition,
  vaultStoreDefinition,
} from '../src/index.js'

const bytes = (text: string) => new TextEncoder().encode(text)

async function fixture() {
  const db = new HozonDB({ adapter: new NodeSQLiteAdapter({ database: ':memory:' }) })
  db.register(vaultStoreDefinition)
  db.register(vaultRecordsStoreDefinition)
  await getVaultRecordsStore(db, VAULT_OP_KIND)
  const identity = randomIdentity()
  const signer = createSigningIdentityForDID(
    'did:test:provider-issuer',
    ed25519.utils.randomSecretKey(),
  )
  const signingKey = { alg: 'EdDSA' as const, publicKey: signer.publicKey }
  const staticMethods: MethodRegistry = [{ method: 'test', resolve: async () => signingKey }]
  let counter = 1000
  const params = {
    mode: 'replicated' as const,
    store: await getVaultStore(db),
    principal: signer.id,
    identity,
    signer,
    runtime: createRuntime(),
    authority: { authorize: async () => true },
    nextHLC: async () => `2026-10-01T00:00:00.000Z:${String(++counter).padStart(8, '0')}:scoped`,
    records: {
      opKind: VAULT_OP_KIND,
      nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
      maxDriftMS: 60_000,
      validateConsumerMetadata: async () => true,
      methods: staticMethods,
    },
  }
  const seed = createVaultCoordinator(params)
  const key = await seed.createKey({ ownerDID: identity.id })
  const entry = await seed.putEntry({
    ...key,
    entryID: 'scoped-entry',
    plaintext: bytes('secret'),
    kind: 'blob',
    label: 'Secret',
    attributes: {},
  })
  const calls: Array<StoreProvider> = []
  const resolved: Array<StoreProvider> = []
  const methodsFor = (provider: StoreProvider): MethodRegistry => {
    calls.push(provider)
    return [
      {
        method: 'test',
        resolve: async (did) => {
          expect(did).toBe(signer.id)
          let timer: ReturnType<typeof setTimeout> | undefined
          try {
            const row = await Promise.race([
              getVaultStore(provider).then((store) => store.getKey(key)),
              new Promise<never>((_, reject) => {
                timer = setTimeout(() => reject(new Error('Resolver query timed out')), 300)
              }),
            ])
            expect(row?.keyID).toBe(key.keyID)
            resolved.push(provider)
            return signingKey
          } finally {
            clearTimeout(timer)
          }
        },
      },
    ]
  }
  const rootMethods = methodsFor(db)
  calls.length = 0
  const manager = createVaultCoordinator({
    ...params,
    methodsFor,
    records: { ...params.records, methods: rootMethods, methodsFor },
  })
  return { db, key, entry, manager, calls, resolved, params, rootMethods, methodsFor }
}

for (const operation of ['read', 'update', 'rotate'] as const) {
  test(`${operation} verifies with the provider of its own transaction`, async () => {
    const f = await fixture()
    try {
      f.calls.length = 0
      if (operation === 'update')
        await f.manager.updateEntry({ ...f.entry, plaintext: bytes('changed') })
      else if (operation === 'rotate')
        expect(await f.manager.rotate({ ...f.key, excludedRecipients: [], reissue: [] })).toBe(2)
      else expect(await f.manager.readEntry(f.entry)).toEqual(bytes('secret'))
      expect(f.calls.some((provider) => provider.isTransactionBound)).toBe(true)
      expect(f.resolved.some((provider) => provider.isTransactionBound)).toBe(true)
      expect(new Set(f.calls).size).toBe(f.calls.length)
      expect(await f.manager.readEntry(f.entry)).toEqual(
        bytes(operation === 'update' ? 'changed' : 'secret'),
      )
    } finally {
      await f.db.close()
    }
  }, 3_000)
}

test('records adapter transactions resolve methods for their provider', async () => {
  const f = await fixture()
  try {
    f.calls.length = 0
    await f.manager.records.adapter.transaction(async (tx) => {
      expect(
        (await tx.get({ type: 'vault.entry', owner: f.entry.ownerDID, id: f.entry.entryID }))
          ?.copies,
      ).toHaveLength(1)
    })
    expect(f.calls.some((provider) => provider.isTransactionBound)).toBe(true)
    expect(f.resolved.some((provider) => provider.isTransactionBound)).toBe(true)
  } finally {
    await f.db.close()
  }
}, 3_000)

test('records apply resolves methods again inside its transaction', async () => {
  const f = await fixture()
  try {
    const records = (await f.manager.records.adapter.list(['vault.entry'])).flatMap(
      (decision) => decision.copies,
    )
    f.calls.length = 0
    f.resolved.length = 0
    const result = await f.manager.records.apply(records)
    expect(result.rejected).toEqual([])
    expect(result.parked).toEqual([])
    expect(f.calls.some((provider) => provider.isTransactionBound)).toBe(true)
    expect(f.resolved.some((provider) => provider.isTransactionBound)).toBe(true)
  } finally {
    await f.db.close()
  }
}, 3_000)

test('coordinator methodsFor also scopes its records when no records factory is supplied', async () => {
  const f = await fixture()
  try {
    const manager = createVaultCoordinator({
      ...f.params,
      methodsFor: f.methodsFor,
      records: { ...f.params.records, methods: f.rootMethods },
    })
    expect(await manager.readEntry(f.entry)).toEqual(bytes('secret'))
    expect(f.resolved.some((provider) => provider.isTransactionBound)).toBe(true)
  } finally {
    await f.db.close()
  }
}, 3_000)

test('methods alone still verifies signed entries', async () => {
  const f = await fixture()
  try {
    const manager = createVaultCoordinator(f.params)
    expect(await manager.readEntry(f.entry)).toEqual(bytes('secret'))
    await manager.updateEntry({ ...f.entry, plaintext: bytes('changed') })
    expect(await manager.readEntry(f.entry)).toEqual(bytes('changed'))
  } finally {
    await f.db.close()
  }
}, 3_000)

test('apply scopes verification hooks while importing a signed branch and its dependants', async () => {
  const f = await fixture()
  const db = new HozonDB({ adapter: new NodeSQLiteAdapter({ database: ':memory:' }) })
  try {
    db.register(vaultStoreDefinition)
    db.register(vaultRecordsStoreDefinition)
    await getVaultRecordsStore(db, VAULT_OP_KIND)
    const records = (
      await f.manager.records.adapter.list([
        'vault.key',
        'vault.key-branch',
        'vault.wrapping',
        'vault.entry',
      ])
    ).flatMap((decision) => decision.copies)
    const providers: Array<StoreProvider> = []
    const methodsFor = (provider: StoreProvider): MethodRegistry => [
      {
        method: 'test',
        resolve: async () => {
          let timer: ReturnType<typeof setTimeout> | undefined
          try {
            await Promise.race([
              getVaultStore(provider).then((store) => store.listKeys(f.key.ownerDID)),
              new Promise<never>((_, reject) => {
                timer = setTimeout(() => reject(new Error('Resolver query timed out')), 300)
              }),
            ])
            providers.push(provider)
            return { alg: 'EdDSA', publicKey: f.params.signer.publicKey }
          } finally {
            clearTimeout(timer)
          }
        },
      },
    ]
    const manager = createVaultCoordinator({
      ...f.params,
      store: await getVaultStore(db),
      records: { ...f.params.records, methods: methodsFor(db), methodsFor },
    })
    const result = await manager.records.apply(records)
    expect(result.rejected).toEqual([])
    expect(result.parked).toEqual([])
    expect(result.applied).toBe(4)
    expect(providers.some((provider) => provider.isTransactionBound)).toBe(true)
    expect(await manager.readEntry(f.entry)).toEqual(bytes('secret'))
  } finally {
    await db.close()
    await f.db.close()
  }
}, 3_000)

test('local row writes own bytes and metadata before waiting for the provider', async () => {
  const db = new HozonDB({ adapter: new NodeSQLiteAdapter({ database: ':memory:' }) })
  db.register(vaultStoreDefinition)
  try {
    const store = await getVaultStore(db)
    const row = {
      ownerDID: randomIdentity().id,
      keyID: 'snapshot-key',
      entryID: 'snapshot-entry',
      keyVersion: 1,
      kind: 'blob',
      label: 'Original',
      attributes: { name: 'original' },
      iv: new Uint8Array(12),
      ciphertext: new Uint8Array([1, 2, 3]),
      hlc: '2026-10-01T00:00:00.000Z:00000001:snapshot',
      provenance: 'local',
    }
    const pending = store.putEntry(row)
    row.label = 'Changed'
    row.attributes.name = 'changed'
    row.ciphertext.fill(9)
    await pending
    const stored = await store.getEntry(row)
    expect(stored?.label).toBe('Original')
    expect(stored?.attributes).toEqual({ name: 'original' })
    expect(stored?.ciphertext).toEqual(new Uint8Array([1, 2, 3]))
  } finally {
    await db.close()
  }
})

test('coordinator writes own plaintext before awaiting authority', async () => {
  const f = await fixture()
  try {
    const entered = Promise.withResolvers<void>()
    const released = Promise.withResolvers<void>()
    const manager = createVaultCoordinator({
      ...f.params,
      authority: {
        authorize: async () => {
          entered.resolve()
          await released.promise
          return true
        },
      },
    })
    const request = { ...f.entry, plaintext: bytes('original') }
    const pending = manager.updateEntry(request)
    await entered.promise
    request.plaintext.fill(9)
    released.resolve()
    await pending
    expect(await manager.readEntry(f.entry)).toEqual(bytes('original'))
  } finally {
    await f.db.close()
  }
})
