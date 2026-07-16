import { beforeEach, describe, expect, test } from 'vitest'

import type { GetStore } from '../src/entry.js'
import { BrowserKeyEntry } from '../src/entry.js'
import { generateKeyRecord, getES256PublicKey, type StoredKeyRecord } from '../src/utils.js'

// --- Mock IDB helpers ---

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

// --- Utils tests (real SubtleCrypto) ---

describe('generateKeyRecord()', () => {
  test('generates a suite-tagged Ed25519 key record', async () => {
    const record = await generateKeyRecord()
    expect(record.suite).toBe('Ed25519')
    expect(record.signing).toBeDefined()
    expect(record.agreement).toBeDefined()
  })

  test('signing key is non-extractable', async () => {
    const record = await generateKeyRecord()
    expect(record.signing.extractable).toBe(false)
  })

  test('signing key allows signing', async () => {
    const record = await generateKeyRecord()
    expect(record.signing.usages).toContain('sign')
  })
})

async function legacyKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
  ])) as CryptoKeyPair
}

describe('getES256PublicKey()', () => {
  test('returns 33-byte compressed public key', async () => {
    const keyPair = await legacyKeyPair()
    const publicKey = await getES256PublicKey(keyPair)
    expect(publicKey).toBeInstanceOf(Uint8Array)
    expect(publicKey.length).toBe(33)
  })

  test('first byte is 0x02 or 0x03 (EC point compression prefix)', async () => {
    const keyPair = await legacyKeyPair()
    const publicKey = await getES256PublicKey(keyPair)
    expect([0x02, 0x03]).toContain(publicKey[0])
  })

  test('same key pair produces same public key', async () => {
    const keyPair = await legacyKeyPair()
    const pk1 = await getES256PublicKey(keyPair)
    const pk2 = await getES256PublicKey(keyPair)
    expect(pk1).toEqual(pk2)
  })
})

// --- Entry tests (mock IDB) ---

describe('BrowserKeyEntry', () => {
  let getStore: GetStore
  let data: Map<string, unknown>

  beforeEach(() => {
    const mock = createMockGetStore()
    getStore = mock.getStore
    data = mock.data
  })

  test('keyID returns the key ID', () => {
    const entry = new BrowserKeyEntry({ keyID: 'k1', getStore })
    expect(entry.keyID).toBe('k1')
  })

  test('getAsync() returns null when key does not exist', async () => {
    const entry = new BrowserKeyEntry({ keyID: 'missing', getStore })
    expect(await entry.getAsync()).toBeNull()
  })

  test('setAsync() stores key and getAsync() retrieves it', async () => {
    const record = await generateKeyRecord()
    const entry = new BrowserKeyEntry({ keyID: 'k2', getStore })
    await entry.setAsync(record)
    const retrieved = await entry.getAsync()
    expect(retrieved).toBe(record)
  })

  test('provideAsync() returns existing key without generating new one', async () => {
    const record = await generateKeyRecord()
    const entry = new BrowserKeyEntry({ keyID: 'k3', getStore })
    await entry.setAsync(record)
    const provided = await entry.provideAsync()
    expect(provided).toBe(record)
  })

  test('provideAsync() generates and stores new key when none exists', async () => {
    const entry = new BrowserKeyEntry({ keyID: 'k4', getStore })
    const provided = (await entry.provideAsync()) as StoredKeyRecord & { suite?: string }
    expect(provided.suite).toBe('Ed25519')
    // Stored in mock IDB
    expect(data.has('k4')).toBe(true)
  })

  test('provideAsync returns the pre-existing key and does not overwrite it', async () => {
    const { getStore, data } = createMockGetStore()
    const seeded = await generateKeyRecord()
    data.set('k', seeded)
    const entry = new BrowserKeyEntry({ keyID: 'k', getStore })
    const result = await entry.provideAsync()
    expect(result).toBe(seeded)
    expect(data.get('k')).toBe(seeded)
  })

  test('removeAsync() deletes key from store', async () => {
    const record = await generateKeyRecord()
    const entry = new BrowserKeyEntry({ keyID: 'k5', getStore })
    await entry.setAsync(record)
    expect(data.has('k5')).toBe(true)
    await entry.removeAsync()
    expect(data.has('k5')).toBe(false)
  })

  test('setAsync rejects when the transaction aborts after the request succeeds', async () => {
    const { getStore, data, abortNextWrite } = createMockGetStore()
    const entry = new BrowserKeyEntry({ keyID: 'k', getStore })
    const record = await generateKeyRecord()
    abortNextWrite()
    await expect(entry.setAsync(record)).rejects.toThrow()
    expect(data.has('k')).toBe(false)
  })
})

// --- Store tests ---

describe('BrowserKeyStore', () => {
  test('entry() returns BrowserKeyEntry with correct keyID', async () => {
    const { BrowserKeyStore } = await import('../src/store.js')
    const store = new BrowserKeyStore(createMockGetStore().getStore)
    const entry = store.entry('my-key')
    expect(entry).toBeInstanceOf(BrowserKeyEntry)
    expect(entry.keyID).toBe('my-key')
  })

  test('entry() returns cached entry for same keyID', async () => {
    const { BrowserKeyStore } = await import('../src/store.js')
    const store = new BrowserKeyStore(createMockGetStore().getStore)
    expect(store.entry('x')).toBe(store.entry('x'))
  })

  test('entry("constructor") returns a real entry, not a prototype member', async () => {
    const { BrowserKeyStore } = await import('../src/store.js')
    const store = new BrowserKeyStore(createMockGetStore().getStore)
    const entry = store.entry('constructor')
    expect(entry).toBeInstanceOf(BrowserKeyEntry)
    expect(entry.keyID).toBe('constructor')
  })
})
