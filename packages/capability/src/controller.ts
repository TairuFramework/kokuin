import {
  CODECS,
  type DIDMethodResolver,
  decodeMultibase,
  encodeMultibase,
  findMethodResolver,
  getAlgorithmAndPublicKey,
  type MethodRegistry,
  normalizeDID,
  type ResolvedSigningKey,
  verifyToken,
} from '@kokuin/token'

import {
  assertCapabilityToken,
  type CapabilityPayload,
  type ConfirmationClaim,
  checkCapability,
  type DelegationChainOptions,
} from './index.js'

/**
 * What the fold does when the capability does not authorise the revoke at all. Every rejection
 * before the audience key is reached collapses into this one: the fold treats it as a failed log,
 * so the difference between "expired" and "wrong resource" changes nothing a caller can act on.
 */
export const REVOKE_NOT_AUTHORISED = 'capability does not authorise this revoke'

/**
 * What the fold does when the capability authorises the revoke but pins no audience key. Distinct
 * from {@link REVOKE_NOT_AUTHORISED} on purpose: the grant is sound and the *capability* is malformed for
 * this use, which is a minting bug in whoever issued it, not a rejected delegation. Distinct from
 * the fold's `revoke is not signed by the capability audience` too — that one means a pin was
 * present and the signature was somebody else's.
 */
export const REVOKE_NO_AUDIENCE_KEY = 'capability pins no audience key'

/** Payload length per signature algorithm, checked after the multicodec prefix is stripped. */
const KEY_LENGTHS: Record<string, number> = { EdDSA: 32, ES256: 33 }

/**
 * Build the `cnf` claim pinning an audience's signing key — see {@link ConfirmationClaim}.
 *
 * The key is encoded exactly as a controller log encodes the keys in `k` — multicodec-tagged, then
 * multibase. Deliberately not a second spelling: the two get compared by a human reading a log next
 * to a capability, and `@kokuin/capability` cannot import the controller's encoder without a cycle,
 * so the format is shared rather than the code. A test asserts the two agree byte for byte.
 *
 * Call it at **mint** time, with the key the audience is known to hold — for a `did:key` audience
 * that key is in the identifier, and for anything else it is whatever `resolveIssuer` answers with
 * at that moment. That moment is the point: the pin is what the issuer saw when it granted, and it
 * never has to be looked up again.
 */
export function audienceConfirmation(key: ResolvedSigningKey): ConfirmationClaim {
  const codec = CODECS[key.alg]
  const bytes = new Uint8Array(codec.length + key.publicKey.length)
  bytes.set(codec, 0)
  bytes.set(key.publicKey, codec.length)
  return { kid: encodeMultibase(bytes) }
}

/**
 * The key a {@link ConfirmationClaim} names. Throws on anything it does not recognise — a missing
 * or non-string `kid`, an unreadable multibase, an unknown codec, a wrong-length payload.
 */
function confirmedKey(cnf: ConfirmationClaim | undefined): ResolvedSigningKey {
  const kid = cnf?.kid
  if (typeof kid !== 'string') {
    throw new Error('Confirmation claim has no kid')
  }
  const info = getAlgorithmAndPublicKey(decodeMultibase(kid))
  if (info == null) {
    throw new Error(`Unrecognised audience key encoding: ${kid}`)
  }
  const [alg, publicKey] = info
  if (publicKey.length !== KEY_LENGTHS[alg]) {
    throw new Error(`Invalid audience key size for ${alg}: ${publicKey.length}`)
  }
  return { alg, publicKey }
}

/**
 * What a capability verifier answers a cap-bearing revoke with — structurally the controller
 * fold's `CapabilityAuthorisation`, which this package cannot import without a cycle. The test
 * passes the built verifier straight into `foldLogAsync` and typechecks, so the two cannot drift.
 */
export type CapabilityAuthorisation =
  | { authorised: true; audienceKey: ResolvedSigningKey }
  | { authorised: false; reason: string }

/**
 * The registry to verify this capability through: the subject answered by the fold's own resolver,
 * everything else by the caller's.
 *
 * The subject's entry **shadows** any same-method entry the caller supplied, and that shadowing is
 * the point. A capability authorising a revoke is issued by the profile whose log carries it, so
 * both questions asked of the subject here — which key signed the capability, and whether the
 * subject has revoked its audience — have to be answered at the log position being verified.
 * `subjectAtPosition` is the only answer that is at that position: a caller's registry is
 * configured once, per DID, with no way to know which event is asking, so it can only be right for
 * one event of a log and is silently wrong for every other. The direction it is wrong in is the
 * dangerous one — a stale prefix does not error, it applies a revoke a denied device authored.
 *
 * The subject's own entry only answers for the subject, so a delegate in the chain that happens to
 * be another profile of the same method still resolves through the caller's registry.
 *
 * `resolveAgreementKey` is deliberately absent: this registry exists for issuer resolution and the
 * deny set, and nothing on a capability path encrypts. A missing `resolveDenySet` on the fallback
 * side answers with the empty set, which is exactly what an absent member already means to
 * `checkCapability`.
 */
function registryForSubject(
  subject: string,
  subjectAtPosition: DIDMethodResolver | undefined,
  methods: MethodRegistry | undefined,
): MethodRegistry | undefined {
  if (subjectAtPosition == null) {
    return methods
  }
  const others = methods ?? []
  const fallback = findMethodResolver(others, subject)
  const pick = (did: string): DIDMethodResolver | undefined =>
    did === subject ? subjectAtPosition : fallback
  const entry: DIDMethodResolver = {
    method: subjectAtPosition.method,
    async resolve(did, header) {
      const resolver = pick(did)
      if (resolver == null) {
        throw new Error(`Unknown DID: ${did}`)
      }
      return await resolver.resolve(did, header)
    },
    async resolveDenySet(did) {
      // Only ever asked about a capability's `sub`, which every capability on this path has already
      // been checked to share with `subject` — so this is the fold's own deny set at the position
      // being verified. The fallback arm exists for the type, not for a reachable case, and an
      // empty set is what an absent member already means to `checkCapability`.
      return (await pick(did)?.resolveDenySet?.(did)) ?? new Set<string>()
    },
  }
  // First, so `findMethodResolver` — which answers with the first entry of a matching method —
  // reaches it rather than the caller's.
  return [entry, ...others]
}

/**
 * A capability-authorised revoke verifier, in the shape a controller fold injects.
 *
 * Named for what it serves, not for what it imports: this file imports nothing from
 * `@kokuin/controller`, which depends on this package's siblings and would be a cycle. The fold
 * takes the callback as an option for exactly that reason, and this is the one real implementation
 * of it — kubun and kumiai must not each grow their own.
 */
export type ControllerCapabilityVerifier = (
  cap: string,
  subject: string,
  target: string,
  /**
   * A resolver for `subject` at the log position being verified, supplied by the fold. Optional
   * only so that a caller can invoke the verifier directly — every fold passes one.
   */
  subjectAtPosition?: DIDMethodResolver,
) => Promise<CapabilityAuthorisation>

/**
 * Build the `verifyCapability` callback a `did:kokuin:` fold needs for a revoke authorised by a
 * capability rather than by the profile's own authority key.
 *
 * The returned function checks, in order:
 *
 * 1. that the serialized capability verifies as a token — against the profile's key state at the
 *    log position being verified, which the fold supplies as the fourth argument;
 * 2. that its `sub` is the controller the fold is running for. This is the binding that stops a
 *    capability minted for one profile from authorising a revoke on another: `act` and `res` say
 *    nothing about *whose* device is being denied;
 * 3. that it grants `{ act: 'revoke', res: <the target DID> }` — including through a delegation
 *    chain, and including a wildcard `res` such as the management capability's. A delegated
 *    capability must carry its parents in its own `cap` claim, since that is where
 *    `checkCapability` walks the chain from; naming a parent only at mint time leaves nothing for
 *    a verifier that sees the event alone;
 * 4. that it pins its audience's signing key in `cnf`.
 *
 * All four passing yields that pinned key. Handing it back rather than a bare `true` is what lets
 * the fold check the revoke event's own signature against it — the audience binding, which nothing
 * on this side of the split can do, because the event is not an argument here and never should be.
 *
 * **The pin is mandatory here, and is never resolved.** Looking the audience up instead would make
 * the *audience's* routine key rotation stop the revoke from verifying, and a revoke that stops
 * verifying makes the whole log unfoldable and the profile's DID permanently unresolvable — a
 * third party bricking an identity by rotating their own key. A capability with no `cnf` is
 * rejected with {@link REVOKE_NO_AUDIENCE_KEY} rather than falling back to resolution, because the
 * fallback is the bug. So is a `cnf` that is present but unreadable — no member this understands,
 * a non-string `kid`, an unknown codec, a wrong-length key.
 *
 * It never throws: a fold that rejected rather than returned would turn every verification failure
 * into an exception on the caller's resolve path.
 *
 * **The subject is never resolved through the caller's registry.** The capability is issued by the
 * very profile whose log carries the revoke, and both questions asked of that profile — which key
 * signed the capability, and whether it has revoked the capability's audience — have to be answered
 * at the position of the event being verified. The fold hands that answer over as
 * `subjectAtPosition` and it shadows any entry the caller supplied for the same method, because a
 * registry configured once per DID cannot be right for more than one position of a log: it has no
 * way to know which event is asking. See {@link registryForSubject}, and
 * `FoldOptions.verifyCapability` in `@kokuin/controller`.
 *
 * That also means `loadLog` answers with the whole log and this verifier needs no resolver of the
 * profile at all — the recursion that made a prefix necessary no longer exists, because verifying
 * the capability no longer resolves the DID being folded.
 *
 * @param options forwarded to `verifyToken` and `checkCapability`. `methods` is needed only for a
 * link in the chain whose own DID method cannot be resolved from the identifier alone — another
 * profile as an intermediate delegate, say. `resolver` and `cache` travel with it for a
 * `did:peer:4` link, and `verifyToken` (the hook) runs on every capability including the one named
 * in the event, which is where a revocation check goes.
 */
export function createControllerCapabilityVerifier(
  options: DelegationChainOptions = {},
): ControllerCapabilityVerifier {
  return async function verifyControllerCapability(
    cap: string,
    subject: string,
    target: string,
    subjectAtPosition?: DIDMethodResolver,
  ): Promise<CapabilityAuthorisation> {
    // The subject is resolved at the position being verified, whatever the caller configured —
    // see {@link registryForSubject}.
    const methods = registryForSubject(subject, subjectAtPosition, options.methods)
    const chainOptions: DelegationChainOptions = { ...options, methods }
    let pinned: ConfirmationClaim | undefined
    try {
      const capability = await verifyToken<CapabilityPayload>(cap, {
        atTime: options.atTime,
        cache: options.cache,
        resolver: options.resolver,
        methods,
      })
      assertCapabilityToken(capability)
      // `checkCapability` runs the hook on every capability it verifies, but it verifies the
      // *parents* of the one handed to it — this one it takes as already established. Running it
      // here is what keeps a revocation check from having a hole exactly at the capability the
      // event names, which is the only one present when the grant is not delegated further.
      await options.verifyToken?.(capability, cap)

      if (normalizeDID(capability.payload.sub) !== normalizeDID(subject)) {
        return { authorised: false, reason: REVOKE_NOT_AUTHORISED }
      }

      await checkCapability({ act: 'revoke', res: target }, capability.payload, chainOptions)
      pinned = capability.payload.cnf
    } catch {
      // Every failure is the same answer here, including the two `@kokuin/token` keeps apart:
      // `UnresolvableIssuerError` (nothing was learned about the capability) and
      // `IssuerKeyNotFoundError` (the issuer resolved and the capability is bad). The distinction
      // exists because a caller that treats "could not check" as "checked and fine" fails open —
      // and this caller does the opposite with both. A rejection makes the fold reject the whole
      // log, so an unverifiable capability leaves the controller unresolvable rather than silently
      // applying a revoke nobody could check.
      return { authorised: false, reason: REVOKE_NOT_AUTHORISED }
    }

    // Outside the catch above so a malformed pin is reported as a malformed pin, rather than
    // disappearing into the generic rejection that every other failure shares.
    if (pinned == null) {
      return { authorised: false, reason: REVOKE_NO_AUDIENCE_KEY }
    }
    try {
      return { authorised: true, audienceKey: confirmedKey(pinned) }
    } catch {
      return { authorised: false, reason: REVOKE_NO_AUDIENCE_KEY }
    }
  }
}
