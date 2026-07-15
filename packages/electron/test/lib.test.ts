import { beforeEach, describe, expect, test, vi } from 'vitest'

// Mock electron safeStorage — identity transform for testing
let encryptionAvailable = true
vi.mock('electron', () => ({
  safeStorage: {
    encryptString: vi.fn((str: string) => Buffer.from(str)),
    decryptString: vi.fn((buf: Buffer) => buf.toString()),
    isEncryptionAvailable: vi.fn(() => encryptionAvailable),
  },
}))

// Mock electron-store — in-memory storage
let storeData: Record<string, Record<string, string>>

vi.mock('electron-store', () => {
  class MockStore {
    name: string
    constructor(options: { name: string }) {
      this.name = options.name
    }
    get(key: string, defaultValue: Record<string, string> = {}) {
      return storeData[this.name]?.[key] != null
        ? JSON.parse(storeData[this.name][key])
        : defaultValue
    }
    set(key: string, value: unknown) {
      storeData[this.name] ??= {}
      storeData[this.name][key] = JSON.stringify(value)
    }
  }
  return { default: MockStore }
})

import { type ElectronKeyEntry, ElectronKeyStore } from '../src/index.js'

beforeEach(() => {
  storeData = {}
  encryptionAvailable = true
})

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

describe('ElectronKeyEntry', () => {
  function createEntry(keyID: string): ElectronKeyEntry {
    return new ElectronKeyStore(`test-${keyID}`).entry(keyID)
  }

  test('keyID returns the key ID', () => {
    expect(createEntry('k1').keyID).toBe('k1')
  })

  test('get() returns null when key does not exist', () => {
    expect(createEntry('missing').get()).toBeNull()
  })

  test('set() stores key and get() retrieves it', () => {
    const entry = createEntry('k2')
    entry.set(bytes('my-private-key'))
    expect(entry.get()).toEqual(bytes('my-private-key'))
  })

  test('get() caches decrypted key', () => {
    const entry = createEntry('k3')
    entry.set(bytes('cached-key'))
    const first = entry.get()
    const second = entry.get()
    expect(first).toBe(second)
  })

  test('provide() returns existing key', () => {
    const entry = createEntry('k4')
    const existing = bytes('existing')
    entry.set(existing)
    expect(entry.provide()).toBe(existing)
  })

  test('provide() generates and stores new key when none exists', () => {
    const entry = createEntry('k5')
    const provided = entry.provide()
    expect(provided).toBeInstanceOf(Uint8Array)
    expect(provided).toHaveLength(32)
    expect(entry.get()).toEqual(provided)
  })

  test('remove() clears key from storage', () => {
    const entry = createEntry('k6')
    entry.set(bytes('to-remove'))
    entry.remove()
    const fresh = new ElectronKeyStore('test-k6').entry('k6')
    expect(fresh.get()).toBeNull()
  })

  test('set() preserves other keys in the same store', () => {
    const store = ElectronKeyStore.open('multi-key')
    store.entry('key-a').set(bytes('secret-a'))
    store.entry('key-b').set(bytes('secret-b'))
    // Read back via a fresh store instance to bypass the entry #key cache
    const fresh = new ElectronKeyStore('multi-key')
    expect(fresh.entry('key-a').get()).toEqual(bytes('secret-a'))
    expect(fresh.entry('key-b').get()).toEqual(bytes('secret-b'))
  })

  // Async variants (wrappers around sync)
  test('getAsync() returns null when key does not exist', async () => {
    expect(await createEntry('ak1').getAsync()).toBeNull()
  })

  test('setAsync() stores key', async () => {
    const entry = createEntry('ak2')
    await entry.setAsync(bytes('async-key'))
    expect(await entry.getAsync()).toEqual(bytes('async-key'))
  })

  test('provideAsync() generates key when none exists', async () => {
    const provided = await createEntry('ak3').provideAsync()
    expect(provided).toBeInstanceOf(Uint8Array)
    expect(provided).toHaveLength(32)
  })

  test('removeAsync() clears key', async () => {
    const entry = createEntry('ak4')
    await entry.setAsync(bytes('temp'))
    await entry.removeAsync()
    const fresh = new ElectronKeyStore('test-ak4').entry('ak4')
    expect(await fresh.getAsync()).toBeNull()
  })
})

describe('ElectronKeyStore', () => {
  test('open() returns singleton for same name', () => {
    const a = ElectronKeyStore.open('singleton-a')
    const b = ElectronKeyStore.open('singleton-a')
    expect(a).toBe(b)
  })

  test('open() returns different instances for different names', () => {
    const a = ElectronKeyStore.open('store-x')
    const b = ElectronKeyStore.open('store-y')
    expect(a).not.toBe(b)
  })

  test('open() defaults to "keystore" name', () => {
    const a = ElectronKeyStore.open()
    const b = ElectronKeyStore.open('keystore')
    expect(a).toBe(b)
  })

  test('entry() returns cached entry for same keyID', () => {
    const store = ElectronKeyStore.open('cache-test')
    expect(store.entry('x')).toBe(store.entry('x'))
  })

  test('entry("constructor") returns a real entry, not a prototype member', () => {
    const store = ElectronKeyStore.open('proto-electron')
    const entry = store.entry('constructor')
    expect(entry.keyID).toBe('constructor')
  })

  test('open() throws on conflicting allowInsecureStorage flag for a cached name', () => {
    ElectronKeyStore.open('flag-conflict', { allowInsecureStorage: false })
    expect(() => ElectronKeyStore.open('flag-conflict', { allowInsecureStorage: true })).toThrow(
      /allowInsecureStorage/i,
    )
  })

  test('open() reuses cached instance when flag matches or is omitted', () => {
    const a = ElectronKeyStore.open('flag-same', { allowInsecureStorage: true })
    expect(ElectronKeyStore.open('flag-same', { allowInsecureStorage: true })).toBe(a)
    expect(ElectronKeyStore.open('flag-same')).toBe(a)
  })
})

describe('ElectronKeyEntry encryption gate', () => {
  test('set() throws when encryption is unavailable', () => {
    encryptionAvailable = false
    const entry = ElectronKeyStore.open('gate-1').entry('k')
    expect(() => entry.set(bytes('secret'))).toThrow(/encryption/i)
  })

  test('allowInsecureStorage bypasses the throw', () => {
    encryptionAvailable = false
    const entry = ElectronKeyStore.open('gate-2', { allowInsecureStorage: true }).entry('k')
    expect(() => entry.set(bytes('secret'))).not.toThrow()
    expect(entry.get()).toEqual(bytes('secret'))
  })

  test('reads still work when encryption is unavailable', () => {
    const entry = ElectronKeyStore.open('gate-3').entry('k')
    entry.set(bytes('secret'))
    encryptionAvailable = false
    expect(entry.get()).toEqual(bytes('secret'))
  })

  test('setAsync rejects (not throws synchronously) when encryption unavailable', async () => {
    encryptionAvailable = false
    const entry = ElectronKeyStore.open('gate-async-1').entry('k')
    await expect(entry.setAsync(bytes('secret'))).rejects.toThrow(/encryption/i)
  })

  test('provideAsync rejects when encryption unavailable', async () => {
    encryptionAvailable = false
    const entry = ElectronKeyStore.open('gate-async-2').entry('k')
    await expect(entry.provideAsync()).rejects.toThrow(/encryption/i)
  })
})

describe('ElectronKeyStore#provideIdentitySync / #provideIdentity', () => {
  test('provideIdentitySync creates identity from store instance', () => {
    const store = ElectronKeyStore.open('eid-1')
    const identity = store.provideIdentitySync('k1')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(identity.signToken).toBeInstanceOf(Function)
  })

  test('provideIdentitySync creates identity from a store opened by name', () => {
    const store = ElectronKeyStore.open('eid-2')
    const identity = store.provideIdentitySync('k1')
    expect(identity.id).toMatch(/^did:key:z/)
  })

  test('provideIdentity (async) works', async () => {
    const store = ElectronKeyStore.open('eid-3')
    const identity = await store.provideIdentity('k1')
    expect(identity.id).toMatch(/^did:key:z/)
  })
})
