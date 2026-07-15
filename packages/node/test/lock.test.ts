import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

let mockKeyring: Record<string, string>
/** Runs inside the locked section, before the re-read — simulates a peer that won the race. */
let onBeforeRead: (() => void) | null = null

vi.mock('@napi-rs/keyring', () => {
  class MockAsyncEntry {
    account: string
    constructor(_service: string, account: string) {
      this.account = account
    }
    async getPassword() {
      onBeforeRead?.()
      onBeforeRead = null
      return mockKeyring[this.account] ?? null
    }
    async setPassword(password: string) {
      mockKeyring[this.account] = password
    }
    async deletePassword() {
      delete mockKeyring[this.account]
    }
  }
  // Not `extends MockAsyncEntry`: the real @napi-rs/keyring `Entry` and `AsyncEntry` are
  // unrelated classes, and a sync override of an async base method is a TS variance error.
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
  return {
    Entry: MockEntry,
    AsyncEntry: MockAsyncEntry,
    findCredentials: vi.fn(() => []),
    findCredentialsAsync: vi.fn(async () => []),
  }
})

const { toB64 } = await import('@sozai/codec')
const { NodeKeyStore } = await import('../src/store.js')
const { NodeKeyEntry } = await import('../src/entry.js')

let dir: string
let lockPath: string

beforeEach(async () => {
  // A null-prototype object, not `{}`: a plain object literal collides with '__proto__' and
  // 'constructor' keyIDs via JS's own prototype chain (unrelated to the code under test), which
  // would make the prototype-pollution cases below fail on the mock rather than on production
  // behavior. A real OS keyring has no such surface, so this keeps the mock faithful to that.
  mockKeyring = Object.create(null)
  onBeforeRead = null
  dir = await mkdtemp(join(tmpdir(), 'kokuin-lock-'))
  lockPath = join(dir, 'keystore.lock')
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('NodeKeyStore lockPath', () => {
  test('provideAsync works with a lockPath set', async () => {
    const store = new NodeKeyStore('lock-basic', { lockPath })
    const key = await store.entry('user').provideAsync()
    expect(key).toHaveLength(32)
    expect(mockKeyring.user).toBe(toB64(key))
  })

  test('re-reads inside the lock and returns a peer’s key rather than clobbering it', async () => {
    const store = new NodeKeyStore('lock-reread', { lockPath })
    const peerKey = crypto.getRandomValues(new Uint8Array(32))

    // The peer writes the credential while we are waiting for the lock. The re-read inside
    // the locked section must see it — without that step the winner overwrites the peer.
    onBeforeRead = () => {
      mockKeyring.user = toB64(peerKey)
    }

    const key = await store.entry('user').provideAsync()
    expect(key).toEqual(peerKey)
    expect(mockKeyring.user).toBe(toB64(peerKey))
  })

  test('concurrent provideAsync calls converge on one key', async () => {
    const store = new NodeKeyStore('lock-concurrent', { lockPath })
    const entry = store.entry('user')
    const keys = await Promise.all([
      entry.provideAsync(),
      entry.provideAsync(),
      entry.provideAsync(),
    ])
    expect(keys[1]).toEqual(keys[0])
    expect(keys[2]).toEqual(keys[0])
    expect(Object.keys(mockKeyring)).toEqual(['user'])
  })

  test('re-reads inside the lock even when #encoded carries a stale list()-time snapshot', async () => {
    // Mirrors what NodeKeyStore#toEntry does: an entry obtained via list()/listAsync() is
    // constructed with `encoded` already set from `credential.password` at list time. If the
    // locked re-read only cleared #key and not #encoded, get()/getAsync() would rehydrate from
    // this stale snapshot instead of observing a peer's write inside the lock.
    const staleKey = crypto.getRandomValues(new Uint8Array(32))
    const peerKey = crypto.getRandomValues(new Uint8Array(32))
    mockKeyring.user = toB64(peerKey)

    const entry = new NodeKeyEntry('lock-encoded', 'user', toB64(staleKey), lockPath)
    const key = await entry.provideAsync()

    expect(key).toEqual(peerKey)
    expect(key).not.toEqual(staleKey)
  })

  test('a lockPath does not leak a lockfile after the call', async () => {
    const store = new NodeKeyStore('lock-cleanup', { lockPath })
    await store.entry('user').provideAsync()
    const { existsSync } = await import('node:fs')
    expect(existsSync(lockPath)).toBe(false)
  })

  test('the sync provide() refuses to run under a lockPath', () => {
    const store = new NodeKeyStore('lock-sync', { lockPath })
    expect(() => store.entry('user').provide()).toThrow(/lockPath/)
    expect(() => store.provideIdentitySync('user')).toThrow(/lockPath/)
  })

  test('re-opening a service with a conflicting lockPath throws', () => {
    NodeKeyStore.open('conflict', { lockPath })
    expect(() => NodeKeyStore.open('conflict', { lockPath: `${lockPath}.other` })).toThrow(
      /lockPath/,
    )
    // Re-opening with the same lockPath, or with none, is fine.
    expect(NodeKeyStore.open('conflict', { lockPath })).toBe(NodeKeyStore.open('conflict'))
  })
})

describe('adversarial keyIDs', () => {
  // The lockfile is ONE coarse file per store, deliberately: a per-keyID lockfile would derive
  // its filename from an attacker-influenced keyID. These assert that choice actually holds —
  // that no keyID can steer the filesystem.
  test.each([
    '../../../etc/passwd',
    '..\\..\\windows\\system32',
    '/absolute/path',
    'nested/../../escape',
  ])('the path-traversal keyID %j touches nothing outside the lockPath', async (keyID) => {
    const { readdirSync } = await import('node:fs')
    const store = new NodeKeyStore('traversal', { lockPath })

    const entry = store.entry(keyID)
    expect(entry.keyID).toBe(keyID)
    const key = await entry.provideAsync()
    expect(key).toHaveLength(32)

    // The keyID went to the keychain as an opaque string, and the lock used the one path we
    // gave it. Nothing else appeared in the directory.
    expect(mockKeyring[keyID]).toBeDefined()
    expect(readdirSync(dir)).toEqual([])
  })

  test.each([
    '__proto__',
    'constructor',
    'prototype',
  ])('the prototype-pollution keyID %j behaves as an ordinary key', async (keyID) => {
    const store = new NodeKeyStore(`pollution-${keyID}`)
    const entry = store.entry(keyID)
    expect(entry.keyID).toBe(keyID)
    expect(await entry.getAsync()).toBeNull()
    const key = await entry.provideAsync()
    expect(await entry.getAsync()).toEqual(key)
  })
})

describe('corrupt credentials', () => {
  test('a non-base64 stored credential throws rather than yielding a bad key', async () => {
    const store = new NodeKeyStore('corrupt')
    mockKeyring.user = 'not!valid!base64!'
    await expect(store.entry('user').getAsync()).rejects.toThrow()
  })

  test('a truncated key throws rather than signing with the wrong length', async () => {
    const store = new NodeKeyStore('truncated')
    mockKeyring.user = toB64(new Uint8Array(8)) // not 32 bytes
    // Either getAsync rejects, or createFullIdentity does — but it must never silently
    // produce an identity from an 8-byte "key".
    await expect(store.provideIdentity('user')).rejects.toThrow()
  })
})
