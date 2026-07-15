import type { MutableKeyEntry } from '@kokuin/token'
import { randomPrivateKey } from '@kokuin/token'
import { AsyncEntry, Entry } from '@napi-rs/keyring'
import { fromB64, toB64 } from '@sozai/codec'
import { withFileLock } from '@sozai/lock'

export class NodeKeyEntry implements MutableKeyEntry<Uint8Array> {
  #async?: AsyncEntry
  #encoded?: string
  #keyID: string
  #key?: Uint8Array
  #lockPath?: string
  #service: string
  #sync?: Entry
  // Serializes provideAsync within THIS process. Cross-process exclusion is opt-in via
  // `lockPath` (@napi-rs/keyring's write is an unconditional upsert with no compare-and-set,
  // so nothing here can be atomic across processes without a file mutex).
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor(service: string, keyID: string, encoded?: string, lockPath?: string) {
    this.#service = service
    this.#keyID = keyID
    this.#encoded = encoded
    this.#lockPath = lockPath
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
    if (this.#encoded != null) {
      this.#key = fromB64(this.#encoded)
      this.#encoded = undefined
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
    if (this.#encoded != null) {
      this.#key = fromB64(this.#encoded)
      this.#encoded = undefined
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

  /**
   * The stored key, generating one if absent. Synchronous, and therefore **not** cross-process
   * safe — a file mutex cannot be acquired synchronously. Throws when a `lockPath` is set,
   * rather than silently dropping the guarantee the caller asked for.
   */
  provide(): Uint8Array {
    if (this.#lockPath != null) {
      throw new Error(
        'NodeKeyEntry.provide() cannot hold a cross-process lock: a file lock cannot be acquired ' +
          'synchronously. This store was opened with a lockPath — use provideAsync() instead.',
      )
    }
    const existing = this.get()
    if (existing != null) {
      return existing
    }
    const privateKey = randomPrivateKey()
    this.set(privateKey)
    return privateKey
  }

  /** Read-if-absent, generate, write. Serialized in-process, and cross-process when `lockPath` is set. */
  provideAsync(): Promise<Uint8Array> {
    const run = this.#provideLock.then(async () => {
      const lockPath = this.#lockPath
      if (lockPath == null) {
        return await this.#provideUnlocked()
      }
      // Acquisition is bounded and THROWS on timeout — never proceed unlocked, which would
      // drop the guard exactly when contention is real.
      return await withFileLock(lockPath, () => this.#provideUnlocked())
    })
    // Keep the chain alive even if this call rejects, so a failure does not wedge the lock.
    this.#provideLock = run.catch(() => undefined)
    return run
  }

  async #provideUnlocked(): Promise<Uint8Array> {
    // Re-read INSIDE the lock: a peer may have written the credential while we waited. Without
    // this the winner clobbers the peer's key, which is the loss the lock exists to prevent.
    this.#key = undefined
    const existing = await this.getAsync()
    if (existing != null) {
      return existing
    }
    const privateKey = randomPrivateKey()
    await this.setAsync(privateKey)
    return privateKey
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
