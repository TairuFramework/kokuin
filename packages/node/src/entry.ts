import type { KeyEntry } from '@kokuin/token'
import { randomPrivateKey } from '@kokuin/token'
import { AsyncEntry, Entry } from '@napi-rs/keyring'
import { fromB64, toB64 } from '@sozai/codec'

export class NodeKeyEntry implements KeyEntry<Uint8Array> {
  #async?: AsyncEntry
  #keyID: string
  #key?: Uint8Array
  #service: string
  #sync?: Entry
  // Serializes provideAsync within THIS process. A cross-process race on the OS
  // keyring remains possible: @napi-rs/keyring exposes no compare-and-set, so two
  // processes can still both observe null and generate. Not solvable here.
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor(service: string, keyID: string, key?: Uint8Array) {
    this.#service = service
    this.#keyID = keyID
    this.#key = key
  }

  get keyID(): string {
    return this.#keyID
  }

  get #asyncEntry(): AsyncEntry {
    this.#async ??= new AsyncEntry(this.#service, this.#keyID)
    return this.#async
  }

  get #syncEntry(): Entry {
    this.#sync ??= new Entry(this.#service, this.#keyID)
    return this.#sync
  }

  get(): Uint8Array | null {
    if (this.#key != null) {
      return this.#key
    }
    const encoded = this.#syncEntry.getPassword()
    if (encoded == null) {
      return null
    }
    this.#key = fromB64(encoded)
    return this.#key
  }

  async getAsync(): Promise<Uint8Array | null> {
    if (this.#key != null) {
      return this.#key
    }
    const encoded = await this.#asyncEntry.getPassword()
    if (encoded == null) {
      return null
    }
    this.#key = fromB64(encoded)
    return this.#key
  }

  set(key: Uint8Array): void {
    this.#syncEntry.setPassword(toB64(key))
    this.#key = key
  }

  async setAsync(key: Uint8Array): Promise<void> {
    await this.#asyncEntry.setPassword(toB64(key))
    this.#key = key
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
      const privateKey = randomPrivateKey()
      await this.setAsync(privateKey)
      return privateKey
    })
    // Keep the chain alive even if this call rejects, so a failure does not wedge the lock.
    this.#provideLock = run.catch(() => undefined)
    return run
  }

  remove(): void {
    this.#syncEntry.deletePassword()
    this.#key = undefined
  }

  async removeAsync(): Promise<void> {
    await this.#asyncEntry.deletePassword()
    this.#key = undefined
  }
}
