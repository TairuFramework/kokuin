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

export type NodeKeyStoreOptions = {
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

export class NodeKeyStore
  implements KeyStore<Uint8Array, NodeKeyEntry>, IdentityProvider<FullIdentity>
{
  static #byService: Record<string, NodeKeyStore> = Object.create(null)

  static open(service: string, options?: NodeKeyStoreOptions): NodeKeyStore {
    const cached = NodeKeyStore.#byService[service]
    if (cached == null) {
      NodeKeyStore.#byService[service] = new NodeKeyStore(service, options)
      return NodeKeyStore.#byService[service]
    }
    if (options?.lockPath != null && options.lockPath !== cached.#lockPath) {
      throw new Error(
        `NodeKeyStore.open('${service}') was already opened with lockPath: ` +
          `${String(cached.#lockPath)}; cannot reopen with conflicting lockPath: ${options.lockPath}.`,
      )
    }
    return cached
  }

  #entries: Record<string, NodeKeyEntry> = Object.create(null)
  #lockPath?: string
  #service: string

  constructor(service: string, options?: NodeKeyStoreOptions) {
    this.#service = service
    this.#lockPath = options?.lockPath
  }

  #toEntry(credential: Credential): NodeKeyEntry {
    this.#entries[credential.account] ??= new NodeKeyEntry(
      this.#service,
      credential.account,
      credential.password,
      this.#lockPath,
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
    this.#entries[keyID] ??= new NodeKeyEntry(this.#service, keyID, undefined, this.#lockPath)
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
