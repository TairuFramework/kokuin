import type { KeyEntry } from '@kokuin/token'

import { derivePrivateKey } from './derivation.js'

export type HDKeyEntryParams = {
  seed: Uint8Array
  /** The caller's keyID, as passed to `HDKeyStore#entry`. */
  keyID: string
  /** The derivation path `keyID` resolved to. */
  path: string
}

/**
 * A derived HD key.
 *
 * Implements {@link KeyEntry} and **not** `MutableKeyEntry`: an HD key is a pure function of
 * (seed, path). There is nothing to set, and deleting it would not stop it being derivable.
 * Previously `setAsync` threw and `removeAsync` silently resolved without doing anything —
 * the type now says what the substrate can do, so neither method exists.
 *
 * {@link getAsync} never returns `null`: the key can always be derived. That is contract-legal
 * for a derived backend (see `KeyEntry`'s invariant 2), and it means the `existing != null`
 * branch every storage-backed package has is dead code here.
 */
export class HDKeyEntry implements KeyEntry<Uint8Array> {
  #seed: Uint8Array
  #keyID: string
  #path: string
  #cachedKey?: Uint8Array

  constructor(params: HDKeyEntryParams) {
    this.#seed = params.seed
    this.#keyID = params.keyID
    this.#path = params.path
  }

  /** The keyID this entry was created for — NOT the derivation path. See {@link path}. */
  get keyID(): string {
    return this.#keyID
  }

  /** The SLIP-0010 derivation path {@link keyID} resolved to, e.g. `m/44'/876'/0'`. */
  get path(): string {
    return this.#path
  }

  #derive(): Uint8Array {
    this.#cachedKey ??= derivePrivateKey(this.#seed, this.#path)
    return this.#cachedKey
  }

  /** The derived key. Never `null` — a derived key always exists. */
  async getAsync(): Promise<Uint8Array | null> {
    return this.#derive()
  }

  async provideAsync(): Promise<Uint8Array> {
    return this.#derive()
  }
}
