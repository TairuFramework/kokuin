import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import {
  createFullIdentity,
  type FullIdentity,
  type IdentityProvider,
  type KeyStore,
} from '@kokuin/token'
import { getLogger } from '@sozai/log'
import { withSpan, withSyncSpan } from '@sozai/otel'

import { ExpoKeyEntry, type StoreEntryOptions } from './entry.js'

export type ExpoKeyStoreParams = StoreEntryOptions & { crypto?: CryptoProvider }

const tracer = createTracer('keystore.expo')
const logger = getLogger(['kokuin', 'expo'])

export class ExpoKeyStore
  implements KeyStore<Uint8Array, ExpoKeyEntry>, IdentityProvider<FullIdentity>
{
  static #default?: ExpoKeyStore

  /** The process-wide store. `options` apply to every entry it creates. */
  static open(options?: StoreEntryOptions & { crypto?: CryptoProvider }): ExpoKeyStore {
    ExpoKeyStore.#default ??= new ExpoKeyStore(options)
    if ((options?.crypto ?? nobleCrypto) !== ExpoKeyStore.#default.#crypto) {
      throw new Error('Cannot reopen a keystore with conflicting crypto provider')
    }
    return ExpoKeyStore.#default
  }

  #crypto: CryptoProvider
  #entries: Record<string, ExpoKeyEntry> = Object.create(null)
  #options?: StoreEntryOptions

  constructor(options?: ExpoKeyStoreParams) {
    const { crypto, ...entryOptions } = options ?? {}
    this.#crypto = crypto ?? nobleCrypto
    this.#options = options === undefined ? undefined : entryOptions
  }

  /**
   * The entry for `keyID`, cached — `entry(x) === entry(x)`.
   *
   * The old object-literal store created a fresh entry per call, which silently defeated the
   * per-entry `provideAsync` lock, and took an undeclared second `options` argument that the
   * `KeyStore` type does not have. Options now belong to the store.
   */
  entry(keyID: string): ExpoKeyEntry {
    this.#entries[keyID] ??= new ExpoKeyEntry({ ...this.#options, keyID })
    return this.#entries[keyID]
  }

  async provideIdentity(keyID: string): Promise<FullIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'expo' } },
      async (span) => {
        const entry = this.entry(keyID)
        const existing = await entry.getAsync()
        const privateKey = existing ?? (await entry.provideAsync())
        const identity = createFullIdentity({ privateKey, crypto: this.#crypto })
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
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'expo' } },
      (span) => {
        const entry = this.entry(keyID)
        const existing = entry.get()
        const privateKey = existing ?? entry.provide()
        const identity = createFullIdentity({ privateKey, crypto: this.#crypto })
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
