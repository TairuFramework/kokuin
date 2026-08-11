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
  /**
   * The DIDs this subject has revoked: no capability whose `aud` is in the set is valid.
   *
   * Answer for **now** — the subject's current state — not for any position a token names. A
   * capability's own claims are author-supplied and backdatable, so a check anchored to them would
   * let the holder pick a moment before it was revoked.
   *
   * Answering means the set is authoritative, so a subject that cannot be resolved must reject
   * rather than answer with an empty set: to a caller those are opposites, and an empty set reads
   * as "nobody is revoked".
   *
   * Optional, like `resolveAgreementKey`: a method with no revocation concept omits it and
   * `@kokuin/capability` then has nothing to enforce. **A method that can revoke must implement
   * it** — it is the only way the rule reaches a verifier, since `@kokuin/capability` cannot
   * import a method's package without a cycle. It rides this registry rather than a second option
   * of its own precisely so that a caller who wired resolution cannot separately forget to wire
   * enforcement.
   */
  resolveDenySet?(did: string): Promise<ReadonlySet<string>>
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
