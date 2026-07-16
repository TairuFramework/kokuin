import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import {
  createFullIdentity,
  type FullIdentity,
  type IdentityProvider,
  type KeyStore,
} from '@kokuin/token'
import { getLogger } from '@sozai/log'
import { withSpan, withSyncSpan } from '@sozai/otel'
import Store from 'electron-store'

import { ElectronKeyEntry } from './entry.js'
import type { KeyStorage } from './types.js'

type StoreValues = { keys: Record<string, string> }

const tracer = createTracer('keystore.electron')
const logger = getLogger(['kokuin', 'electron'])

export type ElectronKeyStoreParams = {
  /** The electron-store file name. Defaults to `'keystore'`. */
  name?: string
  allowInsecureStorage?: boolean
  /**
   * Path to a lockfile enabling **cross-process** exclusion on `provideAsync`.
   *
   * Absent, nothing touches the filesystem and only the in-process lock applies — two
   * processes can still both generate a key for a fresh keyID, and the loser's key is lost.
   *
   * A **file**, not a directory: one coarse lock per store, not one per keyID. A per-keyID
   * lockfile would derive its name from an attacker-influenced keyID (`entry('../../etc/x')`),
   * and `provideAsync` runs once per identity, so serializing across keyIDs costs nothing real.
   *
   * Must be on a local filesystem (`link()` is not atomic on NFS). Acquisition is bounded and
   * throws `TimeoutInterruption` on expiry — it never proceeds unlocked.
   */
  lockPath?: string
}

export class ElectronKeyStore
  implements KeyStore<Uint8Array, ElectronKeyEntry>, IdentityProvider<FullIdentity>
{
  static #byName: Record<string, ElectronKeyStore> = Object.create(null)

  static open(params?: ElectronKeyStoreParams): ElectronKeyStore {
    const name = params?.name ?? 'keystore'
    const cached = ElectronKeyStore.#byName[name]
    if (cached == null) {
      ElectronKeyStore.#byName[name] = new ElectronKeyStore(params)
      return ElectronKeyStore.#byName[name]
    }
    if (
      params?.allowInsecureStorage != null &&
      params.allowInsecureStorage !== cached.#allowInsecureStorage
    ) {
      throw new Error(
        `ElectronKeyStore.open('${name}') was already opened with allowInsecureStorage: ` +
          `${cached.#allowInsecureStorage}; cannot reopen with conflicting allowInsecureStorage: ` +
          `${params.allowInsecureStorage}.`,
      )
    }
    if (params?.lockPath != null && params.lockPath !== cached.#lockPath) {
      throw new Error(
        `ElectronKeyStore.open('${name}') was already opened with lockPath: ` +
          `${String(cached.#lockPath)}; cannot reopen with conflicting lockPath: ${params.lockPath}.`,
      )
    }
    return cached
  }

  #entries: Record<string, ElectronKeyEntry> = Object.create(null)
  #storage: KeyStorage
  #allowInsecureStorage: boolean
  #lockPath?: string

  constructor(params?: ElectronKeyStoreParams) {
    this.#allowInsecureStorage = params?.allowInsecureStorage ?? false
    this.#lockPath = params?.lockPath
    const store = new Store<StoreValues>({
      name: params?.name ?? 'keystore',
      schema: {
        keys: {
          type: 'object',
          properties: {
            key: { type: 'string' },
          },
        },
      },
      defaults: {
        keys: {},
      },
    })
    this.#storage = {
      // Copy onto a null prototype: the object electron-store hands back is JSON-derived and
      // inherits Object.prototype, which makes '__proto__' and 'constructor' hazardous keyIDs.
      getKeys: () => Object.assign(Object.create(null), store.get('keys', {})),
      setKeys: (keys) => store.set('keys', { ...keys }),
    }
  }

  entry(keyID: string): ElectronKeyEntry {
    this.#entries[keyID] ??= new ElectronKeyEntry({
      storage: this.#storage,
      keyID,
      allowInsecureStorage: this.#allowInsecureStorage,
      lockPath: this.#lockPath,
    })
    return this.#entries[keyID]
  }

  async provideIdentity(keyID: string): Promise<FullIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'electron' } },
      async (span) => {
        const entry = this.entry(keyID)
        const existing = await entry.getAsync()
        const privateKey = existing ?? (await entry.provideAsync())
        const identity = createFullIdentity(privateKey)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, existing == null)
        if (existing == null) {
          logger.info('New identity generated: {did}', { did: identity.id })
        }
        return identity
      },
    )
  }

  /** {@link provideIdentity}, synchronously. Beyond the `IdentityProvider` contract. */
  provideIdentitySync(keyID: string): FullIdentity {
    return withSyncSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'electron' } },
      (span) => {
        const entry = this.entry(keyID)
        const existing = entry.get()
        const privateKey = existing ?? entry.provide()
        const identity = createFullIdentity(privateKey)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, existing == null)
        if (existing == null) {
          logger.info('New identity generated: {did}', { did: identity.id })
        }
        return identity
      },
    )
  }
}
