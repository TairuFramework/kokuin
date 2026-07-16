import { mutableKeyStoreConformanceCases } from '@kokuin/keystore-conformance'
import { describe, expect, test } from 'vitest'

import type { GetStore } from '../src/entry.js'
import { BrowserKeyStore } from '../src/store.js'
import { generateKeyRecord, type StoredKeyRecord } from '../src/utils.js'

function createMockGetStore(): {
  getStore: GetStore
  data: Map<string, unknown>
  abortNextWrite: () => void
} {
  const data = new Map<string, unknown>()
  let abortNext = false

  const getStore: GetStore = () => {
    const tx: Record<string, unknown> = {}
    const finish = (aborted: boolean) => {
      queueMicrotask(() => {
        if (aborted) (tx.onabort as (e: Event) => void)?.({} as Event)
        else (tx.oncomplete as (e: Event) => void)?.({} as Event)
      })
    }
    const store = {
      transaction: tx,
      get(key: string) {
        const result = data.get(key)
        const request: Record<string, unknown> = { result }
        queueMicrotask(() => (request.onsuccess as (e: Event) => void)?.({} as Event))
        finish(false)
        return request as unknown as IDBRequest
      },
      put(value: unknown, key: string) {
        const aborted = abortNext
        abortNext = false
        if (!aborted) data.set(key, value)
        const request: Record<string, unknown> = {}
        queueMicrotask(() => (request.onsuccess as (e: Event) => void)?.({} as Event))
        finish(aborted)
        return request as unknown as IDBRequest
      },
      delete(key: string) {
        data.delete(key)
        const request: Record<string, unknown> = {}
        queueMicrotask(() => (request.onsuccess as (e: Event) => void)?.({} as Event))
        finish(false)
        return request as unknown as IDBRequest
      },
    }
    tx.objectStore = () => store
    return store as unknown as IDBObjectStore
  }

  return { getStore, data, abortNextWrite: () => (abortNext = true) }
}

/** A store wired to a mock IDB, bypassing BrowserKeyStore.open's indexedDB.open. */
function createStore(): BrowserKeyStore {
  return new BrowserKeyStore(createMockGetStore().getStore)
}

function sameRecord(a: StoredKeyRecord, b: StoredKeyRecord): boolean {
  // CryptoKeys are opaque and non-extractable; structured-clone round-trips preserve identity
  // through the mock's Map, so reference equality is the right comparison here.
  return a === b
}

describe('BrowserKeyStore conformance', () => {
  const cases = mutableKeyStoreConformanceCases({
    createStore,
    isSameKey: sameRecord,
    createKey: () => generateKeyRecord(),
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('BrowserKeyStore identities', () => {
  test('provideIdentity yields a did:key EdDSA FullIdentity', async () => {
    const store = createStore()
    const identity = await store.provideIdentity('user')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(typeof identity.decrypt).toBe('function')
    expect((await store.provideIdentity('user')).id).toBe(identity.id)
  })

  test('provideSigningIdentity returns the same identity for a current record', async () => {
    const store = createStore()
    const full = await store.provideIdentity('user')
    expect((await store.provideSigningIdentity('user')).id).toBe(full.id)
  })
})

describe('legacy ES256 records', () => {
  async function storeWithLegacyKey(keyID: string): Promise<BrowserKeyStore> {
    const mock = createMockGetStore()
    const store = new BrowserKeyStore(mock.getStore)
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
    ])
    mock.data.set(keyID, keyPair) // an UNTAGGED record — all a pre-migration key can be
    return store
  }

  test('still sign via provideSigningIdentity', async () => {
    const store = await storeWithLegacyKey('legacy')
    const identity = await store.provideSigningIdentity('legacy')
    const token = await identity.signToken({ sub: 'test' })
    expect(token.header.alg).toBe('ES256')
  })

  test('provideIdentity throws rather than returning something that cannot decrypt', async () => {
    const store = await storeWithLegacyKey('legacy')
    await expect(store.provideIdentity('legacy')).rejects.toThrow(/legacy ES256/)
  })

  test('are never silently re-keyed — the DID stays stable', async () => {
    const store = await storeWithLegacyKey('legacy')
    const first = await store.provideSigningIdentity('legacy')
    await store.provideIdentity('legacy').catch(() => undefined)
    const second = await store.provideSigningIdentity('legacy')
    expect(second.id).toBe(first.id)
  })

  test('a stored suite always wins over the requested one', async () => {
    const store = await storeWithLegacyKey('legacy')
    // provideAsync must NOT mint an Ed25519 record over an existing legacy one.
    const record = await store.entry('legacy').provideAsync()
    expect((record as { suite?: string }).suite).toBeUndefined()
  })
})
