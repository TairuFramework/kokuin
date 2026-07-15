import type { MutableKeyEntry } from '@kokuin/token'
import { fromB64, toB64 } from '@sozai/codec'
import { getLogger } from '@sozai/log'
import * as SecureStore from 'expo-secure-store'

import { randomPrivateKey, randomPrivateKeyAsync } from './utils.js'

const logger = getLogger(['kokuin', 'expo'])

export type StoreEntryOptions = SecureStore.SecureStoreOptions

export class ExpoKeyEntry implements MutableKeyEntry<Uint8Array> {
  #keyID: string
  #options?: StoreEntryOptions
  // Serializes provideAsync within this process. Expo runs a single app process, so there is
  // no cross-process race to guard — unlike node and electron.
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor(keyID: string, options?: StoreEntryOptions) {
    this.#keyID = keyID
    this.#options = options
  }

  get keyID(): string {
    return this.#keyID
  }

  get(): Uint8Array | null {
    const privateKey = SecureStore.getItem(this.#keyID, this.#options)
    return privateKey ? fromB64(privateKey) : null
  }

  async getAsync(): Promise<Uint8Array | null> {
    const privateKey = await SecureStore.getItemAsync(this.#keyID, this.#options)
    return privateKey ? fromB64(privateKey) : null
  }

  set(privateKey: Uint8Array): void {
    SecureStore.setItem(this.#keyID, toB64(privateKey), this.#options)
  }

  async setAsync(privateKey: Uint8Array): Promise<void> {
    await SecureStore.setItemAsync(this.#keyID, toB64(privateKey), this.#options)
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
    const run = this.#provideLock.then(async () => {
      const existing = await this.getAsync()
      if (existing != null) {
        return existing
      }
      const privateKey = await randomPrivateKeyAsync()
      await this.setAsync(privateKey)
      return privateKey
    })
    this.#provideLock = run.catch(() => undefined)
    return run
  }

  /**
   * Delete the key. `expo-secure-store` has no synchronous delete, so this starts the deletion
   * and returns immediately — use {@link removeAsync} when you need to know it completed.
   */
  remove(): void {
    SecureStore.deleteItemAsync(this.#keyID, this.#options).catch((error: unknown) => {
      logger.warn('Failed to remove key {keyID}: {error}', { keyID: this.#keyID, error })
    })
  }

  async removeAsync(): Promise<void> {
    await SecureStore.deleteItemAsync(this.#keyID, this.#options)
  }
}
