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
   * The key this subject signs with **now** — its head keys, and nothing it has rotated away.
   *
   * The safe default, and the one a caller reaches for without thinking: authenticating a live
   * signer asks whether *this* party can sign today, and a key the subject has retired must not
   * answer yes. A method whose key set can change over time therefore answers from its current
   * state alone here, and offers {@link resolveHistoric} for the other question.
   */
  resolve(did: string, header: ResolveIssuerHeader): Promise<ResolvedSigningKey>
  /**
   * The key this subject signed with **at some point in the past**, for verifying an artefact it
   * has already issued.
   *
   * The explicit opt-in half of the split. Accepting a superseded key means accepting a signature
   * from a key the subject may have rotated away *because it was compromised*: the answer is "this
   * profile did once hold this key", never "this profile holds this key". Use it only where the
   * artefact being verified was minted in the past and must survive the subject's routine key
   * hygiene — an already-issued capability, a revocation record, an archived grant — and never to
   * authenticate a live signer, where {@link resolve} is the question.
   *
   * A method whose key set never changes may implement it as an alias of {@link resolve}; the two
   * genuinely coincide there.
   *
   * Optional, so that a hand-rolled resolver written before this member existed still typechecks.
   * Its **absence fails closed**: `resolveIssuerWithDoc` asked for a historic resolution refuses
   * rather than falling back to {@link resolve}, because the fallback would silently answer a
   * different question than the caller asked. A method that can retire keys and wants archived
   * material to keep verifying must implement it — including a *wrapper* around one that does, for
   * the same reason `resolveDenySet` must be forwarded.
   */
  resolveHistoric?(did: string, header: ResolveIssuerHeader): Promise<ResolvedSigningKey>
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
   * What this subject has revoked: no capability whose `aud` is in the set is valid.
   *
   * The entries are DIDs. A method whose revocation vocabulary is wider may put other identifiers
   * in the same set — `did:kokuin:` also denies its own signing keys here, spelled `#<multibase
   * key>` the way a `kid` names one — so a reader must **match, never enumerate**: ask whether the
   * DID in hand is present, rather than treating the set as a list of revoked devices. A DID and a
   * key fragment cannot collide, and a method's own resolver is what enforces the entries this
   * package has no vocabulary for.
   *
   * Answer for **now** — the subject's current state — not for any position a token names. A
   * capability's own claims are author-supplied and backdatable, so a check anchored to them would
   * let the holder pick a moment before it was revoked.
   *
   * Answering means the set is authoritative, so a subject that cannot be resolved must reject
   * rather than answer with an empty set: to a caller those are opposites, and an empty set reads
   * as "nobody is revoked".
   *
   * Optional, like `resolveAgreementKey` — but the two absences do not mean the same thing.
   * Omitting `resolveAgreementKey` says this method has no key agreement; omitting this one
   * **disables enforcement** for every subject of this method, silently and in the direction that
   * passes. So: a method with no revocation concept omits it, and **a method that can revoke must
   * implement it** — including a *wrapper* around one that does. A wrapper that forwards `resolve`
   * and stops there (caching, metrics, tracing) type-checks and turns every denial into a pass;
   * forward this member with it.
   *
   * It rides this registry rather than a second option of its own precisely so that a caller who
   * wired resolution cannot separately forget to wire enforcement — that much is unforgettable at
   * the call site. Requiring it here instead would be a breaking change to every implementation of
   * this interface, including hand-rolled test stubs, for a member most methods have no answer for.
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
