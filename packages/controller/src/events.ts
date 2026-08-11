import type { DIDString, ResolvedSigningKey } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlnopad } from '@scure/base'

import { canonicalBytes, digestOf } from './canonical.js'
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from './derivation.js'
import { decodeKey, encodeKey, tryDecodeKey } from './keys.js'

// Re-exported so the barrel stays unchanged for existing consumers — the encoding now lives in
// `keys.ts`, tagged with a multicodec prefix.
export { decodeKey, encodeKey }

export const DID_PREFIX = 'did:kokuin:'

export type EventType = 'icp' | 'rot' | 'rev'

export type EventCommon = {
  /** Inception format version. Absent must never be inferred; always written. */
  v: 1
  t: EventType
  /** Profile DID. Omitted from an inception, whose hash *is* the DID. */
  i?: string
  /** Generation. Incremented only by a reset. */
  g: number
  /** Sequence within the generation. */
  s: number
  /** Digest of the previous event. Absent on inception. */
  p?: string
  /**
   * Criticality. Lives in the common envelope so a verifier can read it without understanding
   * `t`. An unknown event fails the fold closed when true, and is skipped when false.
   */
  crit: boolean
}

export type InceptionEvent = EventCommon & {
  t: 'icp'
  /** Current authority public keys, multicodec-tagged and multibase-encoded. */
  k: Array<string>
  /**
   * Key agreement public keys — an OR set, never combined. Encrypting to this profile means
   * encrypting to one of these. Carries no pre-rotation commitment: an exposed agreement key
   * discloses past ciphertexts but confers no authority.
   */
  ka: Array<string>
  /** Digests of the next public keys — pre-rotation. */
  n: Array<string>
  /** Signing threshold. */
  kt: number
  /** Rotation threshold. */
  nt: number
  /** Digest of the recovery key. Root-retained; immutable unless a co-signed rotate moves it. */
  r: string
}

export type SignedEvent<E extends EventCommon = EventCommon> = {
  event: E
  /** base64url ed25519 signatures over the canonical event bytes, positional against `event.k`. */
  sigs: Array<string>
  /**
   * The revealed recovery public key, present only on a reset. Pre-rotation means the recovery
   * key is committed as a digest and unpublished until used, so a reset must reveal it for the
   * commitment to be checkable.
   */
  recoveryKey?: string
}

export function signEvent(event: EventCommon, privateKeys: Array<Uint8Array>): Array<string> {
  const bytes = canonicalBytes(event)
  return privateKeys.map((key) => base64urlnopad.encode(ed25519.sign(bytes, key)))
}

/**
 * A published key list: an array of strings.
 *
 * `k`, `n`, `ka` and the deny snapshot are read straight off a parsed event and carried into the
 * folded state, so an absent or scalar member has to be rejected where it is published rather than
 * where it is next read — a state holding a non-array `n` throws in the *next* rotate, one event
 * away from the log that caused it, and a state holding a non-array `k` is a `KeyState` whose type
 * lies. A log arrives from a network peer or an untrusted store, so none of these shapes is ruled
 * out by TypeScript.
 */
function isKeyList(value: unknown): value is Array<string> {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string')
}

/**
 * A key agreement set is valid when non-empty and every entry is a well-formed X25519-tagged key.
 * Shared by every event that carries `ka` — inception, rotate, and reset all publish or republish
 * the agreement key set, and a verifier must reject the same malformed shapes everywhere it appears.
 */
function verifyAgreementKeys(ka: Array<string>): boolean {
  if (!isKeyList(ka) || ka.length === 0) {
    return false
  }
  for (const entry of ka) {
    const key = tryDecodeKey(entry)
    if (key == null || key.alg !== 'X25519') {
      return false
    }
  }
  return true
}

/** Total: a malformed signature or key yields false rather than throwing. */
export function verifySignatures(
  event: EventCommon,
  sigs: Array<string>,
  keys: Array<string>,
): boolean {
  if (!Array.isArray(sigs) || !Array.isArray(keys)) {
    return false
  }
  if (sigs.length !== keys.length || sigs.length === 0) {
    return false
  }
  const bytes = canonicalBytes(event)
  for (let i = 0; i < sigs.length; i++) {
    try {
      const key = tryDecodeKey(keys[i])
      if (key == null || key.alg !== 'EdDSA') {
        return false
      }
      if (!ed25519.verify(base64urlnopad.decode(sigs[i]), bytes, key.publicKey)) {
        return false
      }
    } catch {
      return false
    }
  }
  return true
}

/**
 * Whether one of an event's signatures was made by `key`.
 *
 * The counterpart of {@link verifySignatures} for a signer the *event* does not name: that one
 * checks signatures positionally against a published key set, this one asks whether a particular
 * key — resolved from a DID elsewhere — is among the authors. A capability-authorised revoke needs
 * exactly this and nothing more: its author is the capability's `aud`, which the fold cannot
 * resolve, so it is handed the key and checks the signature itself.
 *
 * Total: a malformed signature, or an algorithm this log's events cannot be signed with, yields
 * `false`. Only EdDSA is accepted, because that is all {@link signEvent} produces — an ES256
 * audience therefore cannot author a revoke, which fails closed and is the honest answer until
 * events grow a second signature algorithm.
 */
export function verifyEventSignedBy(signed: SignedEvent, key: ResolvedSigningKey): boolean {
  // `sigs` needs no array check of its own, and this is the rule the whole file applies: **a guard
  // stays when the value it inspects can reach it in the shape it rejects, even if no test can
  // kill it; it is removed only when that value cannot reach it at all, and the unreachability is
  // pinned by a test.** Here it cannot: this function is unexported, the fold is its only caller,
  // and `isSignedEventShape` has already established that `sigs` is an array of strings —
  // `deleted-guards.test.ts` walks every non-array `sigs` shape to the envelope guard and shows it
  // stopping there. "Unkillable" alone is not the test: several guards below are unkillable and
  // stay, because the shapes they reject do arrive from `JSON.parse` and only reach a rejection at
  // all because something checks.
  if (key.alg !== 'EdDSA' || signed.sigs.length === 0) {
    return false
  }
  const bytes = canonicalBytes(signed.event)
  return signed.sigs.some((sig) => {
    try {
      return ed25519.verify(base64urlnopad.decode(sig), bytes, key.publicKey)
    } catch {
      return false
    }
  })
}

/**
 * Deterministic inception. Contains only seed-derived and canonical material — no timestamp, no
 * nonce, no user label — so its hash, and therefore the DID, is a pure function of the seed and
 * the profile index.
 *
 * A user label must never be added here. The DID depends on every byte, so a mistyped label on
 * recovery would reproduce a different DID.
 */
export function createInception(seed: Uint8Array, profile: number): SignedEvent<InceptionEvent> {
  const current = deriveKeyPair(seed, authorityPath(profile, 0, 0), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, 0, 1), 'EdDSA')
  const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')
  const agreement = deriveKeyPair(seed, agreementPath(profile, 0, 0), 'X25519')

  const event: InceptionEvent = {
    v: 1,
    t: 'icp',
    g: 0,
    s: 0,
    crit: true,
    k: [encodeKey(current.publicKey, 'EdDSA')],
    ka: [encodeKey(agreement.publicKey, 'X25519')],
    n: [digestOf(encodeKey(next.publicKey, 'EdDSA'))],
    kt: 1,
    nt: 1,
    r: digestOf(encodeKey(recovery.publicKey, 'EdDSA')),
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
}

export function didFromInception(event: InceptionEvent): DIDString {
  return `${DID_PREFIX}${digestOf(event)}`
}

export function verifyInception(signed: SignedEvent<InceptionEvent>, did: string): boolean {
  if (signed.event.t !== 'icp' || signed.event.i !== undefined) {
    return false
  }
  // `k`, `n` and `r` go straight into the folded state, where the *next* event reads them — a null
  // `n` throws inside the following rotate, one event away from the log that caused it.
  //
  // The `k` check is unkillable: `verifySignatures` below rejects the same shapes with the same
  // `invalid inception`. It stays anyway, by the rule stated at {@link verifyEventSignedBy} — an
  // inception is self-certifying, so *any* `k` an attacker writes is a body they can sign, and this
  // is the guard that says what a published key list must be rather than the one that happens to
  // read it next.
  if (
    !isKeyList(signed.event.k) ||
    !isKeyList(signed.event.n) ||
    typeof signed.event.r !== 'string'
  ) {
    return false
  }
  if (didFromInception(signed.event) !== did) {
    return false
  }
  // An icp-only log must not be a valid DID publishing no agreement key.
  if (!verifyAgreementKeys(signed.event.ka)) {
    return false
  }
  return verifySignatures(signed.event, signed.sigs, signed.event.k)
}

export type RotateEvent = EventCommon & {
  t: 'rot'
  /** Keys the prior event pre-committed, now revealed, multicodec-tagged and multibase-encoded. */
  k: Array<string>
  /**
   * Key agreement public keys — an OR set, never combined. Carries no pre-rotation commitment.
   */
  ka: Array<string>
  /** Digests of the next public keys — pre-rotation. */
  n: Array<string>
  /** Signing threshold. */
  kt: number
  /** Rotation threshold. */
  nt: number
  /** Recovery-commitment update. Only valid when co-signed by the current recovery key. */
  r?: string
  /** Seal: an anchored external digest, used to pin a high-value grant to a log position. */
  a?: string
  /** Deny-set snapshot. Replaces the accumulated set, pruning it. */
  d?: Array<string>
}

export type CreateRotateOptions = {
  seal?: string
  deny?: Array<string>
  /**
   * Where the currently-active authority key lives — the position of the last `icp`/`rot`, which
   * is the fold's `keyGen`/`keySeq`.
   *
   * Defaults to `prior`'s own position, which is right whenever `prior` established a key. A `rev`
   * does not (Amendment A), so a rotate chained onto one must pass this. Without it the rotate
   * reveals a key one past the *revoke*, which nothing ever pre-committed — the event cannot fold,
   * and a log becomes permanently unrotatable after its first revoke. That also takes the deny-set
   * snapshot with it, since the "cold rotate clearing the deny set" of the spec's remedy ladder is
   * exactly a rotate chained onto revokes.
   */
  keyPosition?: { gen: number; seq: number }
}

/**
 * A rotate reveals the keys the prior event pre-committed and commits the next set. Signed by the
 * newly revealed keys, per KERI, which is what makes a stolen current key unable to rotate.
 *
 * Reproducible from the seed alone unless it carries a seal or a deny snapshot.
 */
export function createRotate(
  seed: Uint8Array,
  profile: number,
  did: string,
  prior: EventCommon,
  options: CreateRotateOptions = {},
): SignedEvent<RotateEvent> {
  const gen = prior.g
  const seq = prior.s + 1
  // The log position and the derivation position are the same thing only until the first revoke —
  // see `CreateRotateOptions.keyPosition`. The key this rotate reveals is the one the last icp/rot
  // pre-committed, which sits one past *its* position, and the agreement key lands at the same
  // index so that `KeyState.keyGen`/`keySeq` names it for a recipient re-deriving from the seed.
  const keyGen = options.keyPosition?.gen ?? gen
  const keySeq = (options.keyPosition?.seq ?? prior.s) + 1
  const current = deriveKeyPair(seed, authorityPath(profile, keyGen, keySeq), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, keyGen, keySeq + 1), 'EdDSA')
  const agreement = deriveKeyPair(seed, agreementPath(profile, keyGen, keySeq), 'X25519')

  const event: RotateEvent = {
    v: 1,
    t: 'rot',
    i: did,
    g: gen,
    s: seq,
    p: digestOf(prior),
    crit: true,
    k: [encodeKey(current.publicKey, 'EdDSA')],
    ka: [encodeKey(agreement.publicKey, 'X25519')],
    n: [digestOf(encodeKey(next.publicKey, 'EdDSA'))],
    kt: 1,
    nt: 1,
    a: options.seal,
    d: options.deny,
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
}

/**
 * Whether the members a rotate publishes into the folded state have the shape the fold will carry.
 *
 * Shared by {@link verifyRotate} and {@link verifyReset}: the two verify different signatures over
 * the same event body, and both hand `k`, `n`, `r` and `d` straight to the next `KeyState`. A reset
 * in particular never verifies against `k` — it verifies against the revealed recovery key — so
 * without this it is the one event that can publish a key set of any shape at all.
 */
function isPublishedRotate(event: RotateEvent): boolean {
  return (
    isKeyList(event.k) &&
    isKeyList(event.n) &&
    (event.r == null || typeof event.r === 'string') &&
    // The deny snapshot replaces the accumulated set, so the fold builds a `Set` from it. A scalar
    // `d` is not iterable and throws there; a string `d` would silently become a set of characters.
    (event.d == null || isKeyList(event.d))
  )
}

/**
 * A rotate is valid when it chains to the prior digest, its revealed keys match the prior
 * event's pre-rotation commitment, and its signatures verify against those keys.
 */
export function verifyRotate(
  signed: SignedEvent<RotateEvent>,
  prior: { digest: string; n: Array<string> },
): boolean {
  const { event, sigs } = signed
  if (event.t !== 'rot' || event.p !== prior.digest) {
    return false
  }
  if (!isPublishedRotate(event)) {
    return false
  }
  if (event.k.length !== prior.n.length) {
    return false
  }
  for (let i = 0; i < event.k.length; i++) {
    if (digestOf(event.k[i]) !== prior.n[i]) {
      return false
    }
  }
  if (!verifyAgreementKeys(event.ka)) {
    return false
  }
  return verifySignatures(event, sigs, event.k)
}

/**
 * A reset: a rotate signed by the recovery key that increments the generation and discards
 * everything under the prior one, including every capability minted there.
 *
 * Anchored to the inception rather than to the log head, which the root recomputes from the seed
 * alone — the recovery key lives on the root-retained derivation branch and its digest is
 * committed in the deterministic inception, so a restored mnemonic can author one with no log
 * knowledge or availability at all. Carries no options: no seal, and `d` is always `[]`, so a
 * reset is a pure function of `(seed, profile, gen)` — two blind resets at the same generation
 * produce identical bytes and resolve as idempotent re-derivation rather than duplicity.
 *
 * The root does not need to know the current generation; it only needs to eventually exceed it,
 * since no attacker can author a competing reset at any generation. A blind root starts at
 * `gen = 1` and retries higher if it learns of one — the cost is a round trip, never loss of
 * control.
 */
export function createReset(
  seed: Uint8Array,
  profile: number,
  gen: number,
): SignedEvent<RotateEvent> {
  if (gen < 1) {
    throw new Error(`Reset: gen must be >= 1, got ${gen}`)
  }

  const inception = createInception(seed, profile)
  const did = didFromInception(inception.event)
  const current = deriveKeyPair(seed, authorityPath(profile, gen, 0), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, gen, 1), 'EdDSA')
  const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')
  const agreement = deriveKeyPair(seed, agreementPath(profile, gen, 0), 'X25519')

  const event: RotateEvent = {
    v: 1,
    t: 'rot',
    i: did,
    g: gen,
    s: 0,
    p: digestOf(inception.event),
    crit: true,
    k: [encodeKey(current.publicKey, 'EdDSA')],
    ka: [encodeKey(agreement.publicKey, 'X25519')],
    n: [digestOf(encodeKey(next.publicKey, 'EdDSA'))],
    kt: 1,
    nt: 1,
    // A reset clears the deny set: every capability under the prior generation is gone anyway.
    d: [],
  }

  return {
    event,
    sigs: signEvent(event, [recovery.privateKey]),
    recoveryKey: encodeKey(recovery.publicKey, 'EdDSA'),
  }
}

/**
 * A reset verifies against the committed recovery digest, not against the pre-rotation set. Both
 * values it needs — the anchor digest and the recovery commitment — come from the inception
 * itself, so passing the inception event makes the pairing impossible to get wrong.
 */
export function verifyReset(signed: SignedEvent<RotateEvent>, inception: InceptionEvent): boolean {
  const { event, sigs } = signed
  if (event.t !== 'rot' || event.p !== digestOf(inception) || event.s !== 0 || event.g < 1) {
    return false
  }
  if (!isPublishedRotate(event)) {
    return false
  }
  if (!Array.isArray(sigs) || sigs.length !== 1) {
    return false
  }
  if (!verifyAgreementKeys(event.ka)) {
    return false
  }
  // The recovery key is committed as a digest in the inception and is not published until it is
  // used, so a reset must carry the revealed key on the signed envelope for the commitment to be
  // checkable.
  const revealed = signed.recoveryKey
  if (revealed == null || digestOf(revealed) !== inception.r) {
    return false
  }
  return verifySignatures(event, sigs, [revealed])
}

export type RevokeEvent = EventCommon & {
  t: 'rev'
  /** The DID to deny. A device DID, never a capability `jti`. */
  x: string
  /** A serialized capability authorising a non-authority signer. Verified in the fold. */
  cap?: string
}

/**
 * Revoke a DID: no capability whose `aud` is that DID is valid from this position onward.
 *
 * Naming the device DID rather than a `jti` makes this one entry per device for that device's
 * life — it covers capabilities the verifier has never seen and covers future re-mints, where
 * per-`jti` revocation would grow with every renewal.
 *
 * `prior` answers "what is the next sequence number and what do I chain to"; `keyPosition`
 * separately answers "where does the currently-active authority key live". They coincide only
 * for an `icp`/`rot` prior, which establish a key at their own `s` — a `rev` prior establishes no
 * key at all, so a revoke chained onto a revoke must still point at the last `icp`/`rot`
 * position, not at the prior revoke's own `s`.
 */
export function createRevoke(
  seed: Uint8Array,
  profile: number,
  did: string,
  prior: EventCommon,
  target: string,
  keyPosition: { gen: number; seq: number },
  options: CreateRevokeOptions = {},
): SignedEvent<RevokeEvent> {
  const current = deriveKeyPair(
    seed,
    authorityPath(profile, keyPosition.gen, keyPosition.seq),
    'EdDSA',
  )
  return createRevokeWithKey(current.privateKey, did, prior, target, options)
}

export type CreateRevokeOptions = {
  /** A serialized capability authorising this signer, when the signer is not an authority key. */
  cap?: string
}

/**
 * Revoke a DID, signing with an Ed25519 key the caller already holds rather than deriving one from
 * the profile seed.
 *
 * This is the builder for the actor a capability-authorised revoke exists for: a device holding a
 * management capability, whose whole point (spec, "authority tiers") is that it never receives the
 * profile sub-seed. `createRevoke` can only sign as the profile itself, so without this the feature
 * had no API — a consumer's only route was to re-implement the event's signing convention against
 * `canonicalBytes`, per consumer, which is the duplication `createControllerCapabilityVerifier`
 * exists to prevent on the verifying side.
 *
 * The key is the audience key the capability pins in `cnf`, and the fold checks the event's
 * signature against exactly that — so the two must be the same key. Ed25519 only, because that is
 * all the log's events can be signed with.
 *
 * Takes the private key rather than an identity because no identity type in this stack can sign
 * raw bytes: `SigningIdentity` signs JWTs, `KeyAgreementIdentity` agrees keys, and a `KeyStore`
 * entry hands back exactly this — the same shape `createSigningIdentity` takes.
 *
 * Produces byte-identical output to {@link createRevoke} given the same key, and there is no
 * `keyPosition`: the position exists only to *derive* a key from a seed.
 */
export function createRevokeWithKey(
  privateKey: Uint8Array,
  did: string,
  prior: EventCommon,
  target: string,
  options: CreateRevokeOptions = {},
): SignedEvent<RevokeEvent> {
  const event: RevokeEvent = {
    v: 1,
    t: 'rev',
    i: did,
    g: prior.g,
    s: prior.s + 1,
    p: digestOf(prior),
    crit: true,
    x: target,
    cap: options.cap,
  }

  return { event, sigs: signEvent(event, [privateKey]) }
}

/** Authority-signed revoke. Capability-authorised revokes are checked in the fold. */
export function verifyRevoke(
  signed: SignedEvent<RevokeEvent>,
  prior: { digest: string; keys: Array<string> },
): boolean {
  const { event, sigs } = signed
  if (event.t !== 'rev' || event.p !== prior.digest) {
    return false
  }
  return verifySignatures(event, sigs, prior.keys)
}
