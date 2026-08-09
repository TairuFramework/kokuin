import type { ResolveIssuerHeader } from './did.js'
import type { SignatureAlgorithm } from './schemas.js'

/** The signing key a DID method resolved for a given issuer and header. */
export type ResolvedSigningKey = {
  alg: SignatureAlgorithm
  publicKey: Uint8Array
}

export type AgreementAlgorithm = 'X25519'

/** A key agreement key a DID method resolved for a recipient. */
export type ResolvedAgreementKey = {
  alg: AgreementAlgorithm
  publicKey: Uint8Array
}

/**
 * A DID method this package can resolve `iss` through without importing its implementation.
 *
 * Methods whose document is a projection of an event log — `did:kokuin:` — cannot be resolved
 * from the identifier alone and cannot be linked from here without a dependency cycle:
 * `@kokuin/controller` depends on this package for signing. Injecting the resolver keeps the
 * dependency one-way.
 */
export type DIDMethodResolver = {
  /** The method segment, without `did:` and without the trailing colon. E.g. `kokuin`. */
  method: string
  resolve(did: string, header: ResolveIssuerHeader): Promise<ResolvedSigningKey>
  /**
   * Resolve the recipient's key agreement key set, in the method's own order.
   *
   * Returns every entry with its algorithm rather than one chosen key: the set is an OR set, and
   * selection belongs to the encrypting package, which knows what it supports. A future hybrid
   * codec then changes one preference list instead of every method implementation.
   *
   * Optional: a method with no key agreement omits it.
   */
  resolveAgreementKey?(did: string): Promise<Array<ResolvedAgreementKey>>
}

export type MethodRegistry = ReadonlyArray<DIDMethodResolver>

/** Total: a malformed DID yields `undefined` rather than throwing. */
export function findMethodResolver(
  registry: MethodRegistry,
  did: string,
): DIDMethodResolver | undefined {
  const parts = did.split(':')
  if (parts.length < 3 || parts[0] !== 'did') {
    return undefined
  }
  const method = parts[1]
  return registry.find((entry) => entry.method === method)
}
