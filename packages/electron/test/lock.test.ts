import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

vi.mock('electron', () => ({
  safeStorage: {
    encryptString: vi.fn((str: string) => Buffer.from(str)),
    decryptString: vi.fn((buf: Buffer) => buf.toString()),
    isEncryptionAvailable: vi.fn(() => true),
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

let dir: string
let lockPath: string

beforeEach(async () => {
  storeData = {}
  dir = await mkdtemp(join(tmpdir(), 'kokuin-lock-'))
  lockPath = join(dir, 'keystore.lock')
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('ElectronKeyStore lockPath', () => {
  test('provideAsync works with a lockPath set', async () => {
    const store = new ElectronKeyStore({ name: 'lock-basic', lockPath })
    expect(await store.entry('user').provideAsync()).toHaveLength(32)
  })

  test('concurrent provideAsync calls converge on one key', async () => {
    const store = new ElectronKeyStore({ name: 'lock-concurrent', lockPath })
    const entry = store.entry('user')
    const keys = await Promise.all([entry.provideAsync(), entry.provideAsync()])
    expect(keys[1]).toEqual(keys[0])
  })

  test('the sync provide() refuses to run under a lockPath', () => {
    const store = new ElectronKeyStore({ name: 'lock-sync', lockPath })
    expect(() => store.entry('user').provide()).toThrow(/lockPath/)
    expect(() => store.provideIdentitySync('user')).toThrow(/lockPath/)
  })

  test('no lockfile is left behind', async () => {
    const store = new ElectronKeyStore({ name: 'lock-cleanup', lockPath })
    await store.entry('user').provideAsync()
    const { existsSync } = await import('node:fs')
    expect(existsSync(lockPath)).toBe(false)
  })

  test('re-opening with a conflicting lockPath throws', () => {
    ElectronKeyStore.open({ name: 'conflict', lockPath })
    expect(() =>
      ElectronKeyStore.open({ name: 'conflict', lockPath: `${lockPath}.other` }),
    ).toThrow(/lockPath/)
  })
})
