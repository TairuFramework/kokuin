import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import type { FullIdentity, IdentityProvider, KeyStore, SigningIdentity } from '@kokuin/token'
import { defer } from '@sozai/async'
import { getLogger } from '@sozai/log'
import { withSpan } from '@sozai/otel'

import { BrowserKeyEntry, type GetStore } from './entry.js'
import { createBrowserIdentity, createLegacyES256Identity } from './identity.js'
import { isLegacyES256Record, type StoredKeyRecord } from './utils.js'

const DEFAULT_DB_NAME = 'kokuin:key-store'
const STORE_NAME = 'keys'

export type BrowserKeyStoreParams = {
  /** The IndexedDB database name. Defaults to `'kokuin:key-store'`. */
  name?: string
}
const tracer = createTracer('keystore.browser')
const logger = getLogger(['kokuin', 'browser'])

function createGetStore(db: IDBDatabase): GetStore {
  return function getStore(mode: IDBTransactionMode = 'readonly'): IDBObjectStore {
    return db.transaction(STORE_NAME, mode).objectStore(STORE_NAME)
  }
}

export class BrowserKeyStore
  implements KeyStore<StoredKeyRecord, BrowserKeyEntry>, IdentityProvider<FullIdentity>
{
  static #byName: Record<string, Promise<BrowserKeyStore>> = Object.create(null)

  static open(params?: BrowserKeyStoreParams): Promise<BrowserKeyStore> {
    const name = params?.name ?? DEFAULT_DB_NAME
    const existing = BrowserKeyStore.#byName[name]
    if (existing != null) {
      return existing
    }

    const { promise, reject, resolve } = defer<BrowserKeyStore>()
    BrowserKeyStore.#byName[name] = promise

    if (typeof globalThis.crypto.subtle === 'undefined') {
      reject(new Error('Unable to open KeyStore: SubtleCrypto is not available'))
      return promise
    }
    if (typeof globalThis.indexedDB === 'undefined') {
      reject(new Error('Unable to open KeyStore: IndexedDB is not available'))
      return promise
    }

    const request = indexedDB.open(name, 1)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(new BrowserKeyStore(createGetStore(request.result)))
    request.onupgradeneeded = (event) => {
      ;(event.target as IDBOpenDBRequest).result.createObjectStore(STORE_NAME)
    }
    return promise
  }

  #entries: Record<string, BrowserKeyEntry> = Object.create(null)
  #getStore: GetStore

  constructor(getStore: GetStore) {
    this.#getStore = getStore
  }

  entry(keyID: string): BrowserKeyEntry {
    this.#entries[keyID] ??= new BrowserKeyEntry({ keyID, getStore: this.#getStore })
    return this.#entries[keyID]
  }

  /**
   * The full identity for `keyID` — signing and decryption.
   *
   * **Throws on a legacy ES256 record.** Such a record physically cannot decrypt (WebCrypto
   * will not let an ECDSA key do `deriveBits`), and it is never silently re-keyed, because
   * that would change the identity's DID. Use {@link provideSigningIdentity} to work with one.
   */
  async provideIdentity(keyID: string): Promise<FullIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'browser' } },
      async (span) => {
        const record = await this.entry(keyID).provideAsync()
        if (isLegacyES256Record(record)) {
          throw new Error(
            `Key "${keyID}" holds a legacy ES256 record, which cannot decrypt. It is not ` +
              "re-keyed automatically: that would change this identity's DID. Use " +
              'provideSigningIdentity() to sign with it, or removeAsync() it first to mint a ' +
              'new Ed25519 identity under a new DID.',
          )
        }
        const identity = await createBrowserIdentity(record)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        logger.info('Browser identity resolved: {did}', { did: identity.id })
        return identity
      },
    )
  }

  /**
   * A signing identity for `keyID`, accepting **both** suites.
   *
   * Returns a `FullIdentity` (a subtype of `SigningIdentity`) for a current record, and an
   * ES256 signing identity for a legacy one. New code should prefer {@link provideIdentity},
   * which promises decryption statically.
   */
  async provideSigningIdentity(keyID: string): Promise<SigningIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'browser' } },
      async (span) => {
        const record = await this.entry(keyID).provideAsync()
        const identity = isLegacyES256Record(record)
          ? await createLegacyES256Identity(record)
          : await createBrowserIdentity(record)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        return identity
      },
    )
  }
}
