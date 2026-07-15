import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import {
  createFullIdentity,
  type FullIdentity,
  type IdentityProvider,
  type KeyStore,
} from '@kokuin/token'
import { type Credential, findCredentials, findCredentialsAsync } from '@napi-rs/keyring'
import { getLogger } from '@sozai/log'
import { withSpan, withSyncSpan } from '@sozai/otel'

import { NodeKeyEntry } from './entry.js'

const tracer = createTracer('keystore.node')
const logger = getLogger(['kokuin', 'node'])

export class NodeKeyStore
  implements KeyStore<Uint8Array, NodeKeyEntry>, IdentityProvider<FullIdentity>
{
  static #byService: Record<string, NodeKeyStore> = Object.create(null)

  static open(service: string): NodeKeyStore {
    NodeKeyStore.#byService[service] ??= new NodeKeyStore(service)
    return NodeKeyStore.#byService[service]
  }

  #entries: Record<string, NodeKeyEntry> = Object.create(null)
  #service: string

  constructor(service: string) {
    this.#service = service
  }

  #toEntry(credential: Credential): NodeKeyEntry {
    this.#entries[credential.account] ??= new NodeKeyEntry(
      this.#service,
      credential.account,
      credential.password,
    )
    return this.#entries[credential.account]
  }

  list(): Array<NodeKeyEntry> {
    return findCredentials(this.#service).map((credential) => this.#toEntry(credential))
  }

  async listAsync(): Promise<Array<NodeKeyEntry>> {
    const credentials = await findCredentialsAsync(this.#service)
    return credentials.map((credential) => this.#toEntry(credential))
  }

  entry(keyID: string): NodeKeyEntry {
    this.#entries[keyID] ??= new NodeKeyEntry(this.#service, keyID)
    return this.#entries[keyID]
  }

  /** The Ed25519 identity for `keyID`, generating and persisting a key if there is none. */
  async provideIdentity(keyID: string): Promise<FullIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'node' } },
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

  /**
   * {@link provideIdentity}, synchronously.
   *
   * Beyond the `IdentityProvider` contract, and **not** cross-process safe: a file lock cannot
   * be acquired synchronously, so this throws when the store was opened with a `lockPath`.
   */
  provideIdentitySync(keyID: string): FullIdentity {
    return withSyncSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'node' } },
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
