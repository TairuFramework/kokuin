import type { KeyEntry } from '@kokuin/token'
import { randomPrivateKey } from '@kokuin/token'
import { fromB64, toB64 } from '@sozai/codec'
import { safeStorage } from 'electron'

import type { KeyStorage } from './types.js'

function encryptKey(encoded: string): string {
  return toB64(safeStorage.encryptString(encoded))
}

function decryptKey(encrypted: string): string {
  return safeStorage.decryptString(Buffer.from(fromB64(encrypted)))
}

// Stored as base64
export class ElectronKeyEntry implements KeyEntry<string> {
  #keyID: string
  #key?: string
  #storage: KeyStorage
  #allowInsecureStorage: boolean

  constructor(storage: KeyStorage, keyID: string, key?: string, allowInsecureStorage = false) {
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

  getAsync(): Promise<string | null> {
    return Promise.resolve(this.get())
  }

  get(): string | null {
    if (this.#key != null) {
      return this.#key
    }
    const encrypted = this.#storage.getKeys()[this.#keyID]
    if (encrypted == null) {
      return null
    }
    const key = decryptKey(encrypted)
    if (key == null) {
      return null
    }
    this.#key = key
    return this.#key
  }

  async setAsync(key: string): Promise<void> {
    return this.set(key)
  }

  set(key: string): void {
    this.#assertEncryptionAvailable()
    const encrypted = encryptKey(key)
    const keys = this.#storage.getKeys()
    keys[this.#keyID] = encrypted
    this.#storage.setKeys(keys)
    this.#key = key
  }

  async provideAsync(): Promise<string> {
    return this.provide()
  }

  provide(): string {
    const existing = this.get()
    if (existing != null) {
      return existing
    }
    const privateKey = toB64(randomPrivateKey())
    this.set(privateKey)
    return privateKey
  }

  removeAsync(): Promise<void> {
    return Promise.resolve(this.remove())
  }

  remove(): void {
    const { [this.#keyID]: _, ...keys } = this.#storage.getKeys()
    this.#storage.setKeys(keys)
    this.#key = undefined
  }
}
