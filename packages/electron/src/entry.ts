import type { MutableKeyEntry } from '@kokuin/token'
import { randomPrivateKey } from '@kokuin/token'
import { fromB64, toB64 } from '@sozai/codec'
import { withFileLock } from '@sozai/lock'
import { safeStorage } from 'electron'

import type { KeyStorage } from './types.js'

/** Encrypt raw key bytes for storage: base64(safeStorage(base64(key))). */
function encryptKey(privateKey: Uint8Array): string {
  return toB64(safeStorage.encryptString(toB64(privateKey)))
}

function decryptKey(encrypted: string): Uint8Array {
  return fromB64(safeStorage.decryptString(Buffer.from(fromB64(encrypted))))
}

export class ElectronKeyEntry implements MutableKeyEntry<Uint8Array> {
  #keyID: string
  #key?: Uint8Array
  #storage: KeyStorage
  #allowInsecureStorage: boolean
  #lockPath?: string
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor(
    storage: KeyStorage,
    keyID: string,
    key?: Uint8Array,
    allowInsecureStorage = false,
    lockPath?: string,
  ) {
    this.#keyID = keyID
    this.#key = key
    this.#storage = storage
    this.#allowInsecureStorage = allowInsecureStorage
    this.#lockPath = lockPath
  }

  #assertEncryptionAvailable(): void {
    if (!this.#allowInsecureStorage && !safeStorage.isEncryptionAvailable()) {
      throw new Error(
        'Electron safeStorage encryption is unavailable (e.g. Linux without a keyring); ' +
          'refusing to persist a plaintext-equivalent private key. ' +
          'Pass { allowInsecureStorage: true } to ElectronKeyStore.open to override.',
      )
    }
  }

  get keyID(): string {
    return this.#keyID
  }

  get(): Uint8Array | null {
    if (this.#key != null) {
      return this.#key
    }
    const encrypted = this.#storage.getKeys()[this.#keyID]
    if (encrypted == null) {
      return null
    }
    this.#key = decryptKey(encrypted)
    return this.#key
  }

  async getAsync(): Promise<Uint8Array | null> {
    return this.get()
  }

  set(privateKey: Uint8Array): void {
    this.#assertEncryptionAvailable()
    const keys = this.#storage.getKeys()
    keys[this.#keyID] = encryptKey(privateKey)
    this.#storage.setKeys(keys)
    this.#key = privateKey
  }

  async setAsync(privateKey: Uint8Array): Promise<void> {
    this.set(privateKey)
  }

  /**
   * The stored key, generating one if absent. Synchronous, and therefore **not** cross-process
   * safe. Throws when a `lockPath` is set rather than silently dropping the guarantee.
   */
  provide(): Uint8Array {
    if (this.#lockPath != null) {
      throw new Error(
        'ElectronKeyEntry.provide() cannot hold a cross-process lock: a file lock cannot be ' +
          'acquired synchronously. This store was opened with a lockPath — use provideAsync().',
      )
    }
    return this.#provideUnlocked()
  }

  provideAsync(): Promise<Uint8Array> {
    const run = this.#provideLock.then(async () => {
      const lockPath = this.#lockPath
      if (lockPath == null) {
        return this.#provideUnlocked()
      }
      return await withFileLock(lockPath, async () => this.#provideUnlocked())
    })
    this.#provideLock = run.catch(() => undefined)
    return run
  }

  /** Read-if-absent, generate, write. The caller owns exclusion. */
  #provideUnlocked(): Uint8Array {
    // Drop the in-memory cache: inside the lock we must see a peer's write, not our own
    // stale read. Without this the winner clobbers the peer's key.
    this.#key = undefined
    const existing = this.get()
    if (existing != null) {
      return existing
    }
    const privateKey = randomPrivateKey()
    this.set(privateKey)
    return privateKey
  }

  remove(): void {
    const keys = this.#storage.getKeys()
    delete keys[this.#keyID]
    this.#storage.setKeys(keys)
    this.#key = undefined
  }

  async removeAsync(): Promise<void> {
    this.remove()
  }
}
