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
  /**
   * The key this subject signs with **now** — its head keys, nothing rotated away. The safe default:
   * authenticating a live signer asks whether *this* party can sign today, so a retired key must not
   * answer yes. {@link resolveHistoric} is the other question.
   */
  resolve(did: string, header: ResolveIssuerHeader): Promise<ResolvedSigningKey>
  /**
   * The key this subject signed with **at some point in the past**, for verifying an artefact it has
   * already issued — the explicit opt-in half of the split. It accepts a key the subject may have
   * rotated away *because it was compromised*, so the answer is "did once hold", never "holds". Use it
   * only for past-minted material that must survive routine key hygiene (a capability, a revocation
   * record, an archived grant), never to authenticate a live signer.
   *
   * A method whose key set never changes may alias it to {@link resolve}. Optional, so a resolver
   * written before this member typechecks, but its **absence fails closed**: `resolveIssuerWithDoc`
   * refuses rather than falling back to {@link resolve}, which would answer a different question. A
   * method that can retire keys must implement it — including a *wrapper* around one that does.
   */
  resolveHistoric?(did: string, header: ResolveIssuerHeader): Promise<ResolvedSigningKey>
  /**
   * Resolve the recipient's key agreement key set, in the method's order. Every entry with its
   * algorithm rather than one chosen key: the set is an OR set, and selection belongs to the
   * encrypting package. Optional: a method with no key agreement omits it.
   */
  resolveAgreementKey?(did: string): Promise<Array<ResolvedAgreementKey>>
  /**
   * What this subject has revoked: no capability whose `aud` is in the set is valid. Entries are DIDs,
   * but a wider vocabulary may add others — `did:kokuin:` also denies its own signing keys, spelled
   * `#<key>` — so a reader must **match, never enumerate**. A DID and a key fragment cannot collide.
   *
   * Answer for **now**, not any position a token names: a capability's claims are backdatable, so an
   * anchored check would let the holder pick a moment before it was revoked. A subject that cannot be
   * resolved must reject, never answer the empty set (which reads as "nobody revoked").
   *
   * Optional, but unlike `resolveAgreementKey` its absence **disables enforcement** for every subject
   * of this method, silently and in the passing direction. So a method with no revocation concept
   * omits it, and **a method that can revoke must implement it — including a *wrapper*** (one
   * forwarding only `resolve` type-checks and turns every denial into a pass). It rides this registry
   * so a caller who wired resolution cannot separately forget enforcement; requiring it here would
   * break every implementation for a member most methods have no answer for.
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
