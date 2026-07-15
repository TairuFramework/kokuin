import { mutableKeyStoreConformanceCases } from '@kokuin/token'
import { beforeEach, describe, expect, test, vi } from 'vitest'

let mockKeyring: Record<string, string>

vi.mock('@napi-rs/keyring', () => {
  class MockEntry {
    account: string
    constructor(_service: string, account: string) {
      this.account = account
    }
    getPassword() {
      return mockKeyring[this.account] ?? null
    }
    setPassword(password: string) {
      mockKeyring[this.account] = password
    }
    deletePassword() {
      delete mockKeyring[this.account]
    }
  }
  class MockAsyncEntry {
    account: string
    constructor(_service: string, account: string) {
      this.account = account
    }
    async getPassword() {
      return mockKeyring[this.account] ?? null
    }
    async setPassword(password: string) {
      mockKeyring[this.account] = password
    }
    async deletePassword() {
      delete mockKeyring[this.account]
    }
  }
  return {
    Entry: MockEntry,
    AsyncEntry: MockAsyncEntry,
    findCredentials: vi.fn(() => []),
    findCredentialsAsync: vi.fn(async () => []),
  }
})

const { NodeKeyStore } = await import('../src/store.js')

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

beforeEach(() => {
  mockKeyring = {}
})

describe('NodeKeyStore conformance', () => {
  let counter = 0
  const cases = mutableKeyStoreConformanceCases({
    // A fresh service per case, so the module-level store cache cannot leak between them.
    createStore: () => new NodeKeyStore(`conformance-${counter++}`),
    isSameKey: sameBytes,
    createKey: () => crypto.getRandomValues(new Uint8Array(32)),
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('NodeKeyStore.provideIdentity', () => {
  test('returns a FullIdentity and is stable across calls', async () => {
    const store = new NodeKeyStore('identity-test')
    const first = await store.provideIdentity('user')
    const second = await store.provideIdentity('user')
    expect(first.id).toMatch(/^did:key:z/)
    expect(second.id).toBe(first.id)
    expect(typeof first.signToken).toBe('function')
    expect(typeof first.decrypt).toBe('function')
    expect(typeof first.agreeKey).toBe('function')
  })

  test('the sync twin agrees with the async one', async () => {
    const store = new NodeKeyStore('identity-sync-test')
    const asyncIdentity = await store.provideIdentity('user')
    expect(store.provideIdentitySync('user').id).toBe(asyncIdentity.id)
  })
})
