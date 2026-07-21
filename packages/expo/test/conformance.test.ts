import { mutableKeyStoreConformanceCases } from '@kokuin/keystore-conformance'
import { beforeEach, describe, expect, test, vi } from 'vitest'

let secureStore: Record<string, string>

vi.mock('expo-secure-store', () => ({
  getItem: vi.fn((key: string) => secureStore[key] ?? null),
  getItemAsync: vi.fn(async (key: string) => secureStore[key] ?? null),
  setItem: vi.fn((key: string, value: string) => {
    secureStore[key] = value
  }),
  setItemAsync: vi.fn(async (key: string, value: string) => {
    secureStore[key] = value
  }),
  deleteItemAsync: vi.fn(async (key: string) => {
    delete secureStore[key]
  }),
}))

vi.mock('expo-crypto', () => ({
  getRandomBytes: vi.fn((size: number) => crypto.getRandomValues(new Uint8Array(size))),
  getRandomBytesAsync: vi.fn(async (size: number) => crypto.getRandomValues(new Uint8Array(size))),
}))

const { ExpoKeyStore } = await import('../src/store.js')

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

beforeEach(() => {
  // A null-prototype object, not `{}`: a plain object literal collides with '__proto__' and
  // 'constructor' keyIDs via JS's own prototype chain (unrelated to the code under test), which
  // would make the prototype-pollution cases below fail on the mock rather than on production
  // behavior. A real OS keychain has no such surface, so this keeps the mock faithful to that.
  secureStore = Object.create(null)
})

describe('ExpoKeyStore conformance', () => {
  const cases = mutableKeyStoreConformanceCases({
    createStore: () => new ExpoKeyStore(),
    isSameKey: sameBytes,
    createKey: () => crypto.getRandomValues(new Uint8Array(32)),
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('ExpoKeyStore', () => {
  test('entry() is cached, so the per-entry provideAsync lock can work', () => {
    const store = new ExpoKeyStore()
    expect(store.entry('user')).toBe(store.entry('user'))
  })

  test('entry() takes only a keyID — options move to construction', () => {
    expect(new ExpoKeyStore().entry.length).toBe(1)
  })

  test.each(['__proto__', 'constructor', 'prototype'])(
    'the prototype-pollution keyID %j behaves as an ordinary key',
    async (keyID) => {
      const store = new ExpoKeyStore()
      const entry = store.entry(keyID)
      expect(entry.keyID).toBe(keyID)
      expect(await entry.getAsync()).toBeNull()
      const key = await entry.provideAsync()
      expect(await entry.getAsync()).toEqual(key)
    },
  )

  test('provideIdentity returns a stable FullIdentity', async () => {
    const store = new ExpoKeyStore()
    const identity = await store.provideIdentity('user')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(store.provideIdentitySync('user').id).toBe(identity.id)
  })
})

describe('corrupt credentials', () => {
  test('a non-base64 stored credential throws rather than yielding a bad key', async () => {
    secureStore.user = 'not!valid!base64!'
    await expect(new ExpoKeyStore().entry('user').getAsync()).rejects.toThrow()
  })

  test('a truncated key never becomes a silently wrong identity', async () => {
    secureStore.user = 'AAAAAAAAAAA=' // 8 bytes, not 32
    await expect(new ExpoKeyStore().provideIdentity('user')).rejects.toThrow()
  })
})
