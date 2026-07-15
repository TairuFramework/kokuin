import type { MutableKeyEntry } from '@kokuin/token'
import { randomPrivateKey } from '@kokuin/token'
import { fromB64, toB64 } from '@sozai/codec'
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
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor(storage: KeyStorage, keyID: string, key?: Uint8Array, allowInsecureStorage = false) {
    this.#keyID = keyID
    this.#key = key
    this.#storage = storage
    this.#allowInsecureStorage = allowInsecureStorage
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

  provide(): Uint8Array {
    const existing = this.get()
    if (existing != null) {
      return existing
    }
    const privateKey = randomPrivateKey()
    this.set(privateKey)
    return privateKey
  }

  provideAsync(): Promise<Uint8Array> {
    const run = this.#provideLock.then(async () => this.provide())
    this.#provideLock = run.catch(() => undefined)
    return run
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
