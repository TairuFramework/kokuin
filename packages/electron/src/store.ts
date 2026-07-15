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

export type ElectronKeyStoreOptions = {
  allowInsecureStorage?: boolean
}

export class ElectronKeyStore
  implements KeyStore<Uint8Array, ElectronKeyEntry>, IdentityProvider<FullIdentity>
{
  static #byName: Record<string, ElectronKeyStore> = Object.create(null)

  static open(name = 'keystore', options?: ElectronKeyStoreOptions): ElectronKeyStore {
    const cached = ElectronKeyStore.#byName[name]
    if (cached == null) {
      ElectronKeyStore.#byName[name] = new ElectronKeyStore(name, options)
      return ElectronKeyStore.#byName[name]
    }
    if (
      options?.allowInsecureStorage != null &&
      options.allowInsecureStorage !== cached.#allowInsecureStorage
    ) {
      throw new Error(
        `ElectronKeyStore.open('${name}') was already opened with allowInsecureStorage: ` +
          `${cached.#allowInsecureStorage}; cannot reopen with conflicting allowInsecureStorage: ` +
          `${options.allowInsecureStorage}.`,
      )
    }
    return cached
  }

  #entries: Record<string, ElectronKeyEntry> = Object.create(null)
  #storage: KeyStorage
  #allowInsecureStorage: boolean

  constructor(name: string, options?: ElectronKeyStoreOptions) {
    this.#allowInsecureStorage = options?.allowInsecureStorage ?? false
    const store = new Store<StoreValues>({
      name,
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
    this.#entries[keyID] ??= new ElectronKeyEntry(
      this.#storage,
      keyID,
      undefined,
      this.#allowInsecureStorage,
    )
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
