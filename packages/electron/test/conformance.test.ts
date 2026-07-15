import { mutableKeyStoreConformanceCases } from '@kokuin/keystore-conformance'
import { beforeEach, describe, expect, test, vi } from 'vitest'

let encryptionAvailable = true
vi.mock('electron', () => ({
  safeStorage: {
    encryptString: vi.fn((str: string) => Buffer.from(str)),
    decryptString: vi.fn((buf: Buffer) => buf.toString()),
    isEncryptionAvailable: vi.fn(() => encryptionAvailable),
  },
}))

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

const { ElectronKeyStore } = await import('../src/store.js')

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

beforeEach(() => {
  storeData = {}
  encryptionAvailable = true
})

describe('ElectronKeyStore conformance', () => {
  let counter = 0
  const cases = mutableKeyStoreConformanceCases({
    createStore: () => new ElectronKeyStore(`conformance-${counter++}`),
    isSameKey: sameBytes,
    createKey: () => crypto.getRandomValues(new Uint8Array(32)),
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('ElectronKeyStore adversarial input', () => {
  // The audit's Critical #4, never tested here until now.
  test('two keyIDs in one store get two distinct keys, and neither overwrites the other', async () => {
    const store = new ElectronKeyStore('two-keys')
    const alice = await store.entry('alice').provideAsync()
    const bob = await store.entry('bob').provideAsync()
    expect(alice).not.toEqual(bob)
    expect(await store.entry('alice').getAsync()).toEqual(alice)
    expect(await store.entry('bob').getAsync()).toEqual(bob)
  })

  test.each([
    '__proto__',
    'constructor',
    'prototype',
    'toString',
  ])('the prototype-pollution keyID %j behaves as an ordinary key', async (keyID) => {
    const store = new ElectronKeyStore(`pollution-${keyID}`)
    const entry = store.entry(keyID)
    expect(entry.keyID).toBe(keyID)
    // Absent before it is provided — NOT a function inherited from Object.prototype.
    expect(await entry.getAsync()).toBeNull()

    const key = await entry.provideAsync()
    expect(key).toHaveLength(32)
    expect(await entry.getAsync()).toEqual(key)

    // And it did not corrupt the prototype of anything.
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
    expect(await store.entry('ordinary').getAsync()).toBeNull()
  })

  test('a corrupt stored credential throws rather than yielding a bad key', async () => {
    const store = new ElectronKeyStore('corrupt')
    await store.entry('user').provideAsync()
    // Replace the ciphertext with something that is not valid base64.
    storeData.corrupt.keys = JSON.stringify({ user: 'not!valid!base64!' })
    const fresh = new ElectronKeyStore('corrupt')
    await expect(fresh.entry('user').getAsync()).rejects.toThrow()
  })
})

describe('ElectronKeyStore.provideIdentity', () => {
  test('returns a stable FullIdentity', async () => {
    const store = new ElectronKeyStore('identity')
    const first = await store.provideIdentity('user')
    expect(first.id).toMatch(/^did:key:z/)
    expect((await store.provideIdentity('user')).id).toBe(first.id)
    expect(store.provideIdentitySync('user').id).toBe(first.id)
  })
})
