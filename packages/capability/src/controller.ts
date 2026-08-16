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
 * The fold rejected the revoke before reaching the audience key. Every pre-audience rejection
 * collapses here: "expired" vs "wrong resource" changes nothing a caller can act on.
 */
export const REVOKE_NOT_AUTHORISED = 'capability does not authorise this revoke'

/**
 * The grant is sound but pins no audience key -- a minting bug, not a rejected delegation. Distinct
 * from the fold's `revoke is not signed by the capability audience`, where a pin was present and the
 * signature was somebody else's.
 */
export const REVOKE_NO_AUDIENCE_KEY = 'capability pins no audience key'

/**
 * The pinned key (`cnf`) is not one the audience's (`aud`) identifier carries. Authority follows
 * `cnf`, revocation follows `aud`; unless they are the same party the capability grants authority
 * the deny set cannot reach.
 *
 * Checked against the identifier itself, **never by resolving** it -- resolving is the bug `cnf`
 * exists to remove, and a third party's routine key rotation would otherwise make the log unfoldable
 * forever. So only identifiers that carry a key qualify: a `did:key`, and a `did:peer:4` long form
 * (its `authentication` keys). An audience whose identifier carries no key (a `did:kokuin:` profile,
 * a short-form `did:peer:4`) is refused, not passed unbound -- the shape that once accepted the
 * mismatch is given up deliberately as authority nothing can reach.
 *
 * Its own reason rather than {@link REVOKE_NO_AUDIENCE_KEY}: a pin is present and well formed, and
 * what is wrong is the binding. Refusal lands at verification (an unfoldable log); the mint-side
 * twin {@link assertRevokeCapabilityAudience} applies the same rule where the mistake is cheap.
 */
export const REVOKE_AUDIENCE_KEY_MISMATCH = 'capability pins a key the audience does not carry'

/**
 * The verifier was called without the log position it must verify at (the fourth argument).
 *
 * Required, and enforced at runtime: a type cannot stop an older `@kokuin/controller` calling with
 * three arguments, and nothing ties the two package versions together. Without the position the call
 * falls back to the caller's registry -- the pre-fix behaviour, where an early prefix authorises a
 * revoke by a device the log revoked later. Failing closed makes version skew a rejected log, not a
 * silent bypass.
 */
export const REVOKE_NO_POSITION = 'capability verifier was called without a log position'

/**
 * The authorising capability never expires. An omitted `exp` is permanent, not merely long: the only
 * remedy left is the deny set (the owner noticing and acting), where a bounded grant lapses on its
 * own whether or not anyone noticed.
 *
 * Presence is mandated; length is not. The management capability is minted by the cold root (a
 * Ledger, a mnemonic in a safe), so a short ceiling would mean reaching for the hardware weekly and
 * get worked around. Callers wanting a ceiling pass `maxLifetimeSeconds`.
 */
export const REVOKE_UNBOUNDED_LIFETIME = 'capability authorising a revoke sets no expiry'

/** What the fold does when the capability's lifetime exceeds a configured `maxLifetimeSeconds`. */
export const REVOKE_LIFETIME_TOO_LONG = 'capability authorising a revoke outlives the policy'

/** Payload length per signature algorithm, checked after the multicodec prefix is stripped. */
const KEY_LENGTHS: Record<string, number> = { EdDSA: 32, ES256: 33 }

/**
 * Build the `cnf` claim pinning an audience's signing key -- see {@link ConfirmationClaim}.
 *
 * Encoded exactly as a controller log encodes `k` (multicodec-tagged, then multibase), so a human
 * can compare a log against a capability by eye; the format is shared rather than the code, since
 * importing the controller's encoder would cycle. A test asserts the two agree byte for byte.
 *
 * Call at mint time, with the key the audience holds -- from the identifier for a `did:key`, from
 * `resolveIssuer` for anything else. On the revoke path the pin is also checked against the
 * audience's *identifier*, so mint for a `did:key` or a `did:peer:4` **long form**: a short form is
 * a hash and carries no key. See {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
 */
export function audienceConfirmation(key: ResolvedSigningKey): ConfirmationClaim {
  const codec = CODECS[key.alg]
  const bytes = new Uint8Array(codec.length + key.publicKey.length)
  bytes.set(codec, 0)
  bytes.set(key.publicKey, codec.length)
  return { kid: encodeMultibase(bytes) }
}

/**
 * The key a {@link ConfirmationClaim} names. Throws on anything it does not recognise -- a missing
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
 * The signing keys a DID carries in its identifier, or `null` when it carries none. `did:key` is its
 * key; a `did:peer:4` long form embeds the document, so its `authentication` keys (signing is what
 * the pin is for) are readable from the string. Anything network-backed answers `null` rather than
 * looking up -- see {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
 *
 * Throws on an identifier that claims to carry a key and does not; the caller treats that as no
 * match.
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
      // Legal-but-unsupported multibase, or another key kind: not the pin either way, and one
      // unreadable entry must not hide a readable one below.
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
 * Whether the pinned key fails to name the audience -- the binding that keeps the party wielding the
 * capability and the party the deny set can name the same one. Never resolves the audience. An
 * identifier carrying no key at all fails this rather than passing unbound: a pin nobody can check is
 * no binding. See {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
 */
function contradictsAudience(aud: unknown, pinned: ResolvedSigningKey): boolean {
  if (typeof aud !== 'string') {
    return true
  }
  let carried: Array<ResolvedSigningKey> | null
  try {
    carried = identifierKeys(aud)
  } catch {
    // Claims to carry a key and does not: whatever the pin is, it is not this audience's, and nothing
    // about it starts working later.
    return true
  }
  return carried == null || !carried.some((key) => isSameKey(key, pinned))
}

/**
 * Refuse at mint time to grant `revoke` to an audience that cannot be bound to its own key -- the
 * same rule {@link createControllerCapabilityVerifier} enforces at verification, where the cost is
 * an unfoldable log and a DID that stops resolving rather than a cheap error.
 *
 * Two ways to fail: no `cnf` pin, and a pin the audience's identifier does not carry (including an
 * audience that carries no key, such as a `did:kokuin:` profile or a short-form `did:peer:4`). Name
 * the audience by a `did:key`, or a `did:peer:4` **long form**.
 *
 * Not called from `createCapability`: `act: 'revoke'` is an ordinary action for everything that is
 * not a controller log. Call it yourself when minting for the log.
 */
export function assertRevokeCapabilityAudience(payload: {
  aud?: unknown
  cnf?: ConfirmationClaim
}): void {
  if (payload.cnf == null) {
    throw new Error(`Invalid capability: ${REVOKE_NO_AUDIENCE_KEY}`)
  }
  let pinned: ResolvedSigningKey
  try {
    pinned = confirmedKey(payload.cnf)
  } catch (cause) {
    throw new Error(`Invalid capability: ${REVOKE_NO_AUDIENCE_KEY}`, { cause })
  }
  if (contradictsAudience(payload.aud, pinned)) {
    throw new Error(`Invalid capability: ${REVOKE_AUDIENCE_KEY_MISMATCH}`)
  }
}

/**
 * What a cap-bearing revoke verifier answers -- structurally the controller fold's
 * `CapabilityAuthorisation`, which this package cannot import without a cycle. A test passes the
 * built verifier straight into `foldLogAsync` and typechecks, so the two cannot drift.
 */
export type CapabilityAuthorisation =
  | { authorised: true; audienceKey: ResolvedSigningKey }
  | { authorised: false; reason: string }

/**
 * The registry to verify this capability through: the subject via the fold's own position resolver,
 * everything else via the caller's.
 *
 * The subject's entry **shadows** any same-method entry the caller supplied. A capability
 * authorising a revoke is issued by the profile whose log carries it, so both questions asked of the
 * subject -- which key signed the capability, and whether the subject has revoked its audience --
 * must be answered at the position being verified. A caller's registry is configured once per DID
 * and cannot know which event is asking, so it is silently wrong for every position but one, in the
 * dangerous direction: it applies a revoke a denied device authored. A delegate that is another
 * profile of the same method still resolves through the caller's registry.
 *
 * **Cost, stated plainly: inside the fold, the caller's own `resolve` and `resolveDenySet` for the
 * subject are not consulted.** That is strictly better authority -- derived from the very events
 * being authenticated on a self-certifying DID, and position-aware, which no registry is. A caller
 * still gets a say through the `verifyToken` hook, which throws to reject.
 *
 * `resolveAgreementKey` is absent: nothing on a capability path encrypts. A missing `resolveDenySet`
 * on the fallback side means the empty set (an absent member already does, to `checkCapability`); on
 * the **subject** side it throws, since there the empty set would switch the fold's own rule off.
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
    // Forwarded, not dropped: a capability is archived material (`HISTORIC_ISSUANCE` in `index.ts`),
    // so `verifyToken` asks this member for it. Forwarding only `resolve` would fail every
    // cap-authorised revoke closed -- an unfoldable log, the DID permanently unresolvable. Absent on
    // the position resolver, absent here, and `resolveIssuerWithDoc` refuses rather than silently
    // falling back to `resolve`. `createStateResolver` always publishes it.
    resolveHistoric:
      subjectAtPosition.resolveHistoric == null && fallback?.resolveHistoric == null
        ? undefined
        : async (did, header) => {
            const resolver = pick(did)
            if (resolver?.resolveHistoric == null) {
              throw new Error(`Unknown DID: ${did}`)
            }
            return await resolver.resolveHistoric(did, header)
          },
    async resolveDenySet(did) {
      // Only ever asked about a capability's `sub`, already checked to equal `subject` -- so this is
      // the fold's own deny set at the verified position, the whole of the rule inside the fold.
      // Absent, throw: `createStateResolver` always publishes one, so its absence is a broken caller
      // that forwarded only the member it knew. The empty set would read as "nobody revoked" and
      // turn a denied manager authorised -- the deny set disabled from outside the package. Throwing
      // fails closed (an unfoldable log); with no deny set there is no third option.
      if (did === subject) {
        if (subjectAtPosition.resolveDenySet == null) {
          throw new Error(`Position resolver for ${subject} publishes no deny set`)
        }
        return await subjectAtPosition.resolveDenySet(did)
      }
      // Fallback arm: a same-method delegate resolved through the caller's registry. Empty set is
      // what an absent member already means to `checkCapability` outside a fold.
      return (await fallback?.resolveDenySet?.(did)) ?? new Set<string>()
    },
  }
  // First, so `findMethodResolver` (first matching-method entry wins) reaches it, not the caller's.
  return [entry, ...others]
}

/**
 * What a controller fold hands its verifier. Structurally the fold's `VerifyCapabilityParams`, kept
 * as a local definition rather than an import: importing `@kokuin/controller` would cycle, so the
 * fold takes the verifier as an option and the two shapes match by structure.
 */
export type ControllerCapabilityVerifierParams = {
  cap: string
  subject: string
  target: string
  /**
   * A resolver for `subject` at the log position being verified, supplied by the fold.
   *
   * **Required.** There is no correct answer without it, and obtaining one means folding the log
   * anyway -- at which point the fold is calling this. An implementation handed nothing here must
   * refuse; see {@link REVOKE_NO_POSITION}.
   */
  subjectAtPosition: DIDMethodResolver
}

/**
 * A capability-authorised revoke verifier, in the shape a controller fold injects. Named for what it
 * serves, not what it imports. The one real implementation -- kubun and kumiai must not each grow
 * their own.
 */
export type ControllerCapabilityVerifier = (
  params: ControllerCapabilityVerifierParams,
) => Promise<CapabilityAuthorisation>

/**
 * Build the `verifyCapability` callback a `did:kokuin:` fold needs when a revoke is authorised by a
 * capability rather than the profile's own authority key.
 *
 * Checks, in order:
 *
 * 1. the serialized capability verifies as a token, against the profile's key state at the log
 *    position (the fold supplies it as the fourth argument);
 * 2. its `sub` is the controller the fold runs for -- the binding that stops a capability minted for
 *    one profile authorising a revoke on another (`act`/`res` say nothing about *whose* device);
 * 3. it grants `{ act: 'revoke', res: <target DID> }`, through any delegation chain and including a
 *    wildcard `res`. A delegated capability must carry its parents in its own `cap` claim, since
 *    that is where `checkCapability` walks from;
 * 4. it pins a `cnf` key that does not contradict the audience's own identifier. Authority follows
 *    the pin, revocation follows `aud`, and the binding makes them one party; see
 *    {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
 *
 * All four yield the pinned key, handed back (not a bare `true`) so the fold can check the revoke
 * event's own signature against it -- the event is not, and must not be, an argument here.
 *
 * **The pin is mandatory, never resolved, and must be the audience's own key.** Resolving instead
 * would let the audience's routine rotation stop the revoke verifying, which makes the whole log
 * unfoldable and the DID unresolvable -- a third party bricking an identity by rotating their own
 * key. A missing or unreadable `cnf` is rejected ({@link REVOKE_NO_AUDIENCE_KEY}), not resolved.
 *
 * Never throws: a rejection must not become an exception on the caller's resolve path.
 *
 * The subject is never resolved through the caller's registry -- see {@link registryForSubject}, and
 * `FoldOptions.verifyCapability` in `@kokuin/controller`. The fourth argument is required; its
 * absence is {@link REVOKE_NO_POSITION}, not a worked-around fallback. Invoking this directly is no
 * shortcut around folding: obtaining that argument *is* folding.
 *
 * @param options forwarded to `verifyToken` and `checkCapability`. `methods` is needed only for a
 * chain link whose DID method cannot be resolved from the identifier alone (another profile as an
 * intermediate delegate); `resolver`/`cache` travel with it for a `did:peer:4` link, and the
 * `verifyToken` hook runs on every capability including the one the event names.
 */
export function createControllerCapabilityVerifier(
  options: DelegationChainOptions & { maxLifetimeSeconds?: number } = {},
): ControllerCapabilityVerifier {
  return async function verifyControllerCapability({
    cap,
    subject,
    target,
    subjectAtPosition,
  }: ControllerCapabilityVerifierParams): Promise<CapabilityAuthorisation> {
    // Typed required, checked anyway: TypeScript cannot police this across a package boundary or a
    // stale build, and there is no runtime version link. Falling back to `options.methods` here is
    // exactly the bypass this argument closes -- an early prefix authorising a revoke the log later
    // revoked. Refuse.
    if (subjectAtPosition == null) {
      return { authorised: false, reason: REVOKE_NO_POSITION }
    }
    // Subject resolved at the verified position, whatever the caller configured -- see
    // {@link registryForSubject}.
    const methods = registryForSubject(subject, subjectAtPosition, options.methods)
    const chainOptions: DelegationChainOptions = { ...options, methods }
    let pinned: ConfirmationClaim | undefined
    let audience: unknown
    // Reported after the try, not thrown inside it, so a never-expiring capability is told apart from
    // a rejected grant -- different bugs, one the minter's. See {@link REVOKE_UNBOUNDED_LIFETIME}.
    let lifetime: string | undefined
    try {
      const capability = await verifyToken<CapabilityPayload>(cap, {
        atTime: options.atTime,
        cache: options.cache,
        resolver: options.resolver,
        methods,
        // Issued at some position of this log, and the revoke names it later (maybe post-rotate).
        // Verifying against the prefix head's keys alone would let routine rotation unfold the log.
        // The prefix is still the position, so nothing after this event is in scope.
        historic: true,
      })
      assertCapabilityToken(capability)
      // `checkCapability` verifies the *parents* of the capability handed to it, taking this one as
      // established -- so run the hook here too, else the revocation check has a hole exactly at the
      // capability the event names (the only one present when the grant is not delegated further).
      await options.verifyToken?.(capability, cap)

      if (normalizeDID(capability.payload.sub) !== normalizeDID(subject)) {
        return { authorised: false, reason: REVOKE_NOT_AUTHORISED }
      }

      await checkCapability({ act: 'revoke', res: target }, capability.payload, chainOptions)
      const { exp } = capability.payload
      if (exp == null) {
        lifetime = REVOKE_UNBOUNDED_LIFETIME
      } else if (
        options.maxLifetimeSeconds != null &&
        exp - (options.atTime ?? Math.floor(Date.now() / 1000)) > options.maxLifetimeSeconds
      ) {
        lifetime = REVOKE_LIFETIME_TOO_LONG
      }
      pinned = capability.payload.cnf
      audience = capability.payload.aud
    } catch {
      // Every failure is the same answer, including `@kokuin/token`'s two: `UnresolvableIssuerError`
      // ("could not check") and `IssuerKeyNotFoundError` ("resolved, bad"). Both reject -- a
      // rejection makes the fold reject the whole log, so an unverifiable capability leaves the
      // controller unresolvable rather than silently applying an uncheckable revoke.
      return { authorised: false, reason: REVOKE_NOT_AUTHORISED }
    }

    if (lifetime != null) {
      return { authorised: false, reason: lifetime }
    }
    // Outside the catch so a malformed pin reports as one, not the generic rejection.
    if (pinned == null) {
      return { authorised: false, reason: REVOKE_NO_AUDIENCE_KEY }
    }
    let audienceKey: ResolvedSigningKey
    try {
      audienceKey = confirmedKey(pinned)
    } catch {
      return { authorised: false, reason: REVOKE_NO_AUDIENCE_KEY }
    }
    // Pin is well formed; it must still name the audience. Authority follows the pin, revocation
    // follows `aud`, so a mismatch is authority the deny set cannot reach. Checked against the
    // identifier, never by resolving. See {@link REVOKE_AUDIENCE_KEY_MISMATCH}.
    if (contradictsAudience(audience, audienceKey)) {
      return { authorised: false, reason: REVOKE_AUDIENCE_KEY_MISMATCH }
    }
    return { authorised: true, audienceKey }
  }
}
