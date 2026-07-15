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

const tracer = createTracer('keystore.expo')
const logger = getLogger(['kokuin', 'expo'])

export class ExpoKeyStore
  implements KeyStore<Uint8Array, ExpoKeyEntry>, IdentityProvider<FullIdentity>
{
  static #default?: ExpoKeyStore

  /** The process-wide store. `options` apply to every entry it creates. */
  static open(options?: StoreEntryOptions): ExpoKeyStore {
    ExpoKeyStore.#default ??= new ExpoKeyStore(options)
    return ExpoKeyStore.#default
  }

  #entries: Record<string, ExpoKeyEntry> = Object.create(null)
  #options?: StoreEntryOptions

  constructor(options?: StoreEntryOptions) {
    this.#options = options
  }

  /**
   * The entry for `keyID`, cached — `entry(x) === entry(x)`.
   *
   * The old object-literal store created a fresh entry per call, which silently defeated the
   * per-entry `provideAsync` lock, and took an undeclared second `options` argument that the
   * `KeyStore` type does not have. Options now belong to the store.
   */
  entry(keyID: string): ExpoKeyEntry {
    this.#entries[keyID] ??= new ExpoKeyEntry(keyID, this.#options)
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
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'expo' } },
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
