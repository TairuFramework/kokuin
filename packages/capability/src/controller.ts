import {
  CODECS,
  type DIDMethodResolver,
  decodeMultibase,
  decodePeer4,
  encodeMultibase,
  findMethodResolver,
  getAlgorithmAndPublicKey,
  getPeer4ShortForm,
  getSignatureInfo,
  isPeer4,
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

/**
 * What the fold does when the capability pins a key its audience's own identifier does not carry.
 *
 * Authority on this path follows `cnf` — the pinned key is what the revoke event is checked against
 * — while revocation follows `aud`, which is what a `rev` event names and what the deny set holds.
 * Nothing makes the two the same party unless this does, and a capability where they differ is a
 * revoke authority that revoking cannot reach: deny the DID in `aud` and the key in `cnf` carries
 * on, deny the key's own DID and the capability never named it.
 *
 * Its own reason rather than {@link REVOKE_NO_AUDIENCE_KEY}: a pin is present and well formed, and
 * what is wrong is the binding. Both are minting bugs, and a minter told "pins no audience key"
 * about a capability that plainly pins one would look for the wrong thing.
 *
 * The audience is **never resolved** to establish this — resolving is the bug `cnf` exists to
 * remove, and a third party's routine key rotation would otherwise make a profile's log unfoldable
 * forever. The binding is therefore checked against the audience identifier itself, and reaches
 * exactly the identifiers that carry a key: a `did:key`, and a `did:peer:4` long form (its
 * `authentication` keys). Mint for one of those whenever the audience is a device.
 *
 * **What stays open, stated plainly:** an audience whose identifier carries no key — a
 * `did:kokuin:` profile, a short-form `did:peer:4` — cannot be bound to a pin without resolving it,
 * so a capability naming one is accepted with its pin unbound. A minter who chooses such an
 * audience and pins somebody else's key still produces an authority that denying the `aud` does not
 * reach. Refusing that case instead would make one profile's management capability over another
 * unusable and its logs unfoldable, which is the worse failure and the one the standing rule
 * against resolving the audience exists to prevent. The remedy is at mint time: name the audience
 * by a DID that carries its key.
 */
export const REVOKE_AUDIENCE_KEY_MISMATCH = 'capability pins a key the audience does not carry'

/**
 * What a verifier answers when it is called without the log position it must verify at.
 *
 * The fourth argument is required, and this is the runtime half of that: a type cannot stop an
 * *older* `@kokuin/controller` from calling with three arguments, and nothing in the package graph
 * ties the two versions together — `@kokuin/capability` depends on `@kokuin/token` alone. Without
 * this, that call falls back to whatever registry the caller configured, which is the pre-fix
 * behaviour: a registry answering with an early prefix authorises a revoke by a device the log
 * revoked later. Failing closed makes version skew a rejected log rather than a silent bypass.
 *
 * Its own reason rather than {@link REVOKE_NOT_AUTHORISED}, because it says nothing about the
 * capability: the grant was never evaluated.
 */
export const REVOKE_NO_POSITION = 'capability verifier was called without a log position'

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
 *
 * On the controller-revoke path the pin is additionally checked against the audience's *identifier*
 * — the only way to tie the party that wields the capability to the party the deny set can name
 * without resolving anything. Mint for a `did:key` audience, or for a `did:peer:4` **long form**: a
 * short form is a hash of the document and carries no key, so a pin against one cannot be checked
 * at all. See {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
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

/** As long as `resolveKidFromDoc` in `@kokuin/token` allows: base58 decoding is O(n^2). */
const MAX_KEY_ENCODED = 64

/**
 * The signing keys a DID carries in the identifier itself, or `null` when it carries none.
 *
 * `did:key` **is** its key. A `did:peer:4` long form embeds the document, so the keys its
 * `authentication` relationship names are readable from the string alone — and `authentication` is
 * the right relationship because signing is what the audience will do with the pinned key. Anything
 * else — a `did:peer:4` short form, a `did:kokuin:`, anything network-backed — needs a lookup, and
 * answering `null` rather than performing one is the whole point: see
 * {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
 *
 * Throws on an identifier that claims to carry a key and does not — a malformed `did:key`, an
 * undecodable long form. The caller treats that as no match.
 */
function identifierKeys(did: string): Array<ResolvedSigningKey> | null {
  if (did.startsWith('did:key:')) {
    const [alg, publicKey] = getSignatureInfo(did)
    return [{ alg, publicKey }]
  }
  if (!isPeer4(did) || did === getPeer4ShortForm(did)) {
    return null
  }
  const { doc } = decodePeer4(did)
  const keys: Array<ResolvedSigningKey> = []
  for (const id of doc.authentication ?? []) {
    const method = doc.verificationMethod.find((entry) => entry.id === id)
    if (method == null || method.publicKeyMultibase.length > MAX_KEY_ENCODED) {
      continue
    }
    let info: [ResolvedSigningKey['alg'], Uint8Array] | null = null
    try {
      info = getAlgorithmAndPublicKey(decodeMultibase(method.publicKeyMultibase))
    } catch {
      // A legal-but-unsupported multibase, or a key of another kind: it is not the pinned key
      // either way, and one unreadable entry must not hide a readable one further down.
      continue
    }
    if (info != null) {
      keys.push({ alg: info[0], publicKey: info[1] })
    }
  }
  return keys
}

/** Whether two resolved keys are the same key. */
function isSameKey(a: ResolvedSigningKey, b: ResolvedSigningKey): boolean {
  if (a.alg !== b.alg || a.publicKey.length !== b.publicKey.length) {
    return false
  }
  return a.publicKey.every((byte, index) => byte === b.publicKey[index])
}

/**
 * Whether the pinned key contradicts the audience — the binding that keeps the party wielding the
 * capability and the party the deny set can name the same one. Never resolves the audience; see
 * {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
 *
 * An audience whose identifier carries no key at all is **not** a contradiction and is not refused
 * here. That is the `did:kokuin:` case — one profile holding a management capability over another
 * is a supported shape, pinned by a test in `controller-revoke.test.ts` — and its key is knowable
 * only by resolving it, which is the bug the pin exists to remove and a standing rule against.
 * Refusing instead would make every such log unfoldable and the profile's DID permanently
 * unresolvable, which is a far worse failure than the one it would close. What remains open there
 * is stated in {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
 */
function contradictsAudience(aud: unknown, pinned: ResolvedSigningKey): boolean {
  if (typeof aud !== 'string') {
    return true
  }
  let carried: Array<ResolvedSigningKey> | null
  try {
    carried = identifierKeys(aud)
  } catch {
    // An identifier that claims to carry a key and does not: whatever the pin is, it is not that
    // audience's key, and nothing about this can start working later.
    return true
  }
  return carried != null && !carried.some((key) => isSameKey(key, pinned))
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
 * **What shadowing costs, stated plainly: inside the fold, a caller's own `resolve` and
 * `resolveDenySet` for the subject are not consulted at all.** A policy resolver that denies a DID
 * out of band, or one that refuses to answer for this profile, has no effect here — the fold's
 * answer is derived from the very events it is authenticating on a self-certifying DID, which is
 * strictly better authority than anything a registry can be configured with, and unlike a registry
 * it knows which position is asking. A caller wanting a say on this path still has one: the
 * `verifyToken` hook runs on the capability the event names, and throwing from it rejects the
 * revoke.
 *
 * `resolveAgreementKey` is deliberately absent: this registry exists for issuer resolution and the
 * deny set, and nothing on a capability path encrypts. A missing `resolveDenySet` on the fallback
 * side answers with the empty set, which is exactly what an absent member already means to
 * `checkCapability`.
 */
function registryForSubject(
  subject: string,
  subjectAtPosition: DIDMethodResolver,
  methods: MethodRegistry | undefined,
): MethodRegistry {
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
   * A resolver for `subject` at the log position being verified, supplied by the fold.
   *
   * **Required.** It is the whole of what makes a capability-authorised revoke checkable at the
   * position it sits at, and there is no correct answer without it — a caller invoking this
   * directly has to fold the log to obtain one, at which point the fold is calling it anyway. An
   * implementation handed nothing here must refuse; see {@link REVOKE_NO_POSITION}.
   */
  subjectAtPosition: DIDMethodResolver,
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
 * 4. that it pins a signing key in `cnf`, and that the key does not contradict the audience's own
 *    identifier. Authority on this path follows the pin and revocation follows `aud`; the binding
 *    is what makes them the same party, and without it a capability could name a revokable audience
 *    while handing the authority to a key no `rev` event can reach. See
 *    {@link REVOKE_AUDIENCE_KEY_MISMATCH} for why the audience is checked from its identifier
 *    rather than resolved, which audiences that reaches, and what it asks of a minter.
 *
 * All four passing yields that pinned key. Handing it back rather than a bare `true` is what lets
 * the fold check the revoke event's own signature against it — the audience binding, which nothing
 * on this side of the split can do, because the event is not an argument here and never should be.
 *
 * **The pin is mandatory here, is never resolved, and must be the audience's own key.** Looking the
 * audience up instead would make
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
 * **The fourth argument is required, and its absence is refused rather than worked around.** There
 * is no correct answer without it: falling back to the caller's registry is the pre-fix behaviour,
 * where a registry answering with an early prefix authorises a revoke by a device the log revoked
 * later. Every fold supplies one; an older `@kokuin/controller` calling with three arguments —
 * nothing in the package graph ties the two versions together — gets {@link REVOKE_NO_POSITION} and
 * an unfoldable log rather than a silent bypass. Invoking this directly is therefore not a
 * supported shortcut around folding: obtaining the argument *is* folding.
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
    subjectAtPosition: DIDMethodResolver,
  ): Promise<CapabilityAuthorisation> {
    // Typed as required, and checked anyway. TypeScript cannot police this argument across a
    // package boundary or a stale build, and `@kokuin/capability` has no runtime dependency on
    // `@kokuin/controller` to keep the two versions in step — so an older fold calling with three
    // arguments is a real shape. Falling back to `options.methods` for the subject would be exactly
    // the bypass this parameter exists to close: a registry answering with an early prefix
    // authorises a revoke by a device the log revoked later. Refuse instead.
    if (subjectAtPosition == null) {
      return { authorised: false, reason: REVOKE_NO_POSITION }
    }
    // The subject is resolved at the position being verified, whatever the caller configured —
    // see {@link registryForSubject}.
    const methods = registryForSubject(subject, subjectAtPosition, options.methods)
    const chainOptions: DelegationChainOptions = { ...options, methods }
    let pinned: ConfirmationClaim | undefined
    let audience: unknown
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
      audience = capability.payload.aud
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
    let audienceKey: ResolvedSigningKey
    try {
      audienceKey = confirmedKey(pinned)
    } catch {
      return { authorised: false, reason: REVOKE_NO_AUDIENCE_KEY }
    }
    // The pin is well formed; it still has to name the audience. Authority follows the pinned key
    // and revocation follows `aud`, so a capability where they are different parties is one the
    // deny set cannot reach — see {@link REVOKE_AUDIENCE_KEY_MISMATCH}. Checked against the
    // identifier alone, never by resolving the audience.
    if (contradictsAudience(audience, audienceKey)) {
      return { authorised: false, reason: REVOKE_AUDIENCE_KEY_MISMATCH }
    }
    return { authorised: true, audienceKey }
  }
}
