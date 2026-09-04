import type { DIDString, ResolvedSigningKey } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlnopad } from '@scure/base'

import { canonicalBytes, digestOf, isCanonicalizable } from './canonical.js'
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from './derivation.js'
import { encodeKey, tryDecodeKey } from './keys.js'

export const DID_PREFIX = 'did:kokuin:'

export type EventType = 'icp' | 'rot' | 'rev'

// Guard rule this file applies throughout: a total guard stays when the shape it rejects can reach
// it from `JSON.parse` (a log arrives from a peer or untrusted store, so TypeScript rules nothing
// out), even if no test can kill it; it goes only when that shape provably cannot reach it, pinned
// by a test. Such guards state what the code accepts rather than relying on what runs beneath them.

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
   * Criticality. In the common envelope so a verifier reads it without understanding `t`. An unknown
   * event fails the fold closed when true, and is skipped when false.
   */
  crit: boolean
}

export type InceptionEvent = EventCommon & {
  t: 'icp'
  /** Current authority public keys, multicodec-tagged and multibase-encoded. */
  k: Array<string>
  /**
   * Key agreement public keys -- an OR set, never combined. Carries no pre-rotation commitment: an
   * exposed agreement key discloses past ciphertexts but confers no authority.
   */
  ka: Array<string>
  /** Digests of the next public keys — pre-rotation. */
  n: Array<string>
  /** Signing threshold: how many of `k` must sign. **Must equal `k.length`** — see {@link isEnforcedThreshold}. */
  kt: number
  /** Rotation threshold: how many of `n` must sign the next rotate. **Must equal `n.length`.** */
  nt: number
  /**
   * Digest of the recovery key. Root-retained, **immutable for the life of the DID** — the only
   * event that can carry one is this one, and this one is the DID. A rotate carrying `r` is refused
   * rather than ignored — see {@link RotateEvent}.
   */
  r: string
}

export type SignedEvent<E extends EventCommon = EventCommon> = {
  event: E
  /** base64url ed25519 signatures over the canonical event bytes, positional against `event.k`. */
  sigs: Array<string>
  /**
   * The revealed recovery public key, present only on a reset. The recovery key is committed as a
   * digest and unpublished until used, so a reset must reveal it for the commitment to be checkable.
   */
  recoveryKey?: string
}

export function signEvent(event: EventCommon, privateKeys: Array<Uint8Array>): Array<string> {
  const bytes = canonicalBytes(event)
  return privateKeys.map((key) => base64urlnopad.encode(ed25519.sign(bytes, key)))
}

/**
 * Whether a published threshold agrees with what the fold enforces.
 *
 * `kt`/`nt` are published and digested into the event (and, for an inception, the DID), but the fold
 * enforces n-of-n and nothing else: one valid signature per published key, every committed key
 * revealed and signing. So the only threshold these fields can truthfully carry is the size of the
 * set they govern; anything else is an event whose declaration contradicts the rule judging it. A
 * field nothing reads is a trap for the next reader inside a wire format fixed by the DID; if quorum
 * ever lands, the check moves with the enforcement. `===` against the length, so `"1"` fails.
 */
function isEnforcedThreshold(threshold: unknown, keys: Array<string>): boolean {
  return threshold === keys.length
}

/**
 * A published key list: an array of strings. `k`, `n`, `ka` and the deny snapshot are carried into
 * the folded state, so a bad shape must be rejected where it is published, not one event away where
 * it is next read (a non-array `n` would throw in the *next* rotate; a non-array `k` is a `KeyState`
 * whose type lies).
 */
function isKeyList(value: unknown): value is Array<string> {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string')
}

/**
 * A key agreement set is valid when non-empty and every entry is a well-formed X25519-tagged key.
 * Shared by every event that carries `ka` (inception, rotate, reset), which must reject the same
 * malformed shapes everywhere.
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

/**
 * Total: a malformed signature or key yields false rather than throwing, including a body the
 * canonicalizer refuses. `canonicalBytes` throws on a non-finite number or nesting past
 * `MAX_CANONICAL_DEPTH` (both from `JSON.parse`); the fold's envelope guard rejects such a body one
 * layer out, so this is unreachable through `foldLog` but stays because the export is documented
 * total and a direct caller reaches it with a parsed body. `false` is honest: a body with no
 * canonical encoding has no bytes for a signature to be over.
 */
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
  if (!isCanonicalizable(event)) {
    return false
  }
  const bytes = canonicalBytes(event)
  for (const [i, sig] of sigs.entries()) {
    try {
      const encodedKey = keys[i]
      if (encodedKey == null) {
        return false
      }
      const key = tryDecodeKey(encodedKey)
      if (key == null || key.alg !== 'EdDSA') {
        return false
      }
      if (!ed25519.verify(base64urlnopad.decode(sig), bytes, key.publicKey)) {
        return false
      }
    } catch {
      return false
    }
  }
  return true
}

/**
 * Whether one of an event's signatures was made by `key` — the counterpart of
 * {@link verifySignatures} for a signer the *event* does not name (resolved from a DID elsewhere). A
 * capability-authorised revoke needs exactly this: its author is the capability's `aud`, which the
 * fold cannot resolve, so it is handed the key and checks the signature itself.
 *
 * Total, EdDSA only — all {@link signEvent} produces. An ES256 audience therefore cannot author a
 * revoke, which fails closed until events grow a second signature algorithm.
 */
export function verifyEventSignedBy(signed: SignedEvent, key: ResolvedSigningKey): boolean {
  // Both arms are unkillable through the fold (`isSignedEventShape` already established `sigs` is a
  // string array; a non-EdDSA key would fail `ed25519.verify`; `[].some()` is `false`) and both stay
  // by the file's guard rule: a direct caller reaches this with a parsed body.
  if (key.alg !== 'EdDSA' || signed.sigs.length === 0) {
    return false
  }
  if (!isCanonicalizable(signed.event)) {
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
 * Deterministic inception. Only seed-derived, canonical material — no timestamp, nonce, or label —
 * so the DID is a pure function of the seed and profile index. Never add a label: a mistyped one on
 * recovery would reproduce a different DID.
 */
export function createInception(seed: Uint8Array, profile: number): SignedEvent<InceptionEvent> {
  const event = inceptionEvent(seed, profile)
  const current = deriveKeyPair(seed, authorityPath(profile, 0, 0), 'EdDSA')
  return { event, sigs: signEvent(event, [current.privateKey]) }
}

/**
 * The inception body alone, unsigned. Split out because {@link createRotate} needs the DID this seed
 * and profile produce to know whether it is the log's root, and signing a throwaway inception to
 * find out is the one expensive step.
 */
function inceptionEvent(seed: Uint8Array, profile: number): InceptionEvent {
  const current = deriveKeyPair(seed, authorityPath(profile, 0, 0), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, 0, 1), 'EdDSA')
  const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')
  const agreement = deriveKeyPair(seed, agreementPath(profile, 0, 0), 'X25519')

  return {
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
}

export function didFromInception(event: InceptionEvent): DIDString {
  return `${DID_PREFIX}${digestOf(event)}`
}

/** The did:kokuin: identifier a seed and profile produce, without signing an inception. */
export function didFor(seed: Uint8Array, profile: number): DIDString {
  return didFromInception(inceptionEvent(seed, profile))
}

export function verifyInception(signed: SignedEvent<InceptionEvent>, did: string): boolean {
  if (signed.event.t !== 'icp' || signed.event.i !== undefined) {
    return false
  }
  // An inception is self-certifying: *any* body an attacker writes is a valid log for the DID it
  // hashes to, which is why the thresholds and key lists it publishes must mean something. `k`/`n`/`r`
  // go straight into the folded state where the next event reads them.
  if (
    !isKeyList(signed.event.k) ||
    !isKeyList(signed.event.n) ||
    typeof signed.event.r !== 'string'
  ) {
    return false
  }
  if (
    !isEnforcedThreshold(signed.event.kt, signed.event.k) ||
    !isEnforcedThreshold(signed.event.nt, signed.event.n)
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
  /** Key agreement public keys — an OR set, never combined. Carries no pre-rotation commitment. */
  ka: Array<string>
  /** Digests of the next public keys — pre-rotation. */
  n: Array<string>
  /** Signing threshold: how many of `k` must sign. **Must equal `k.length`.** */
  kt: number
  /** Rotation threshold: how many of `n` must sign the next rotate. **Must equal `n.length`.** */
  nt: number
  /**
   * Seal: an anchored external digest pinning a high-value grant to this position. Opaque to the fold
   * by design — its meaning belongs to whatever produced it, and nothing in the key state can
   * contradict it. The fold owes it only that it cannot ride in as a non-string (checked in
   * {@link isPublishedRotate}). Not surfaced in `KeyState`: it belongs to a position, not the keys.
   */
  a?: string
  /** Deny-set snapshot. Replaces the accumulated set, pruning it. */
  d?: Array<string>
}

export type CreateRotateOptions = {
  seal?: string
  /**
   * The complete deny set this rotate leaves behind — **a replacement, not an addition**. `d` present
   * replaces the accumulated set, `d` absent carries it forward. A caller writing one entry meaning
   * "also deny this" silently drops every accumulated entry — un-revoking devices and un-retiring
   * leaked keys — with no error and nothing in the log saying anything was lost. Build it from the
   * folded state with {@link pruneDenySet}. `[]` is the deliberate "clear everything" a cold rotate
   * does to recover from a bad management tier. A rotate cannot establish a key its own snapshot
   * denies; the fold refuses such an event.
   */
  denySnapshot?: Array<string>
  /**
   * Where the currently-active authority key lives — the position of the last `icp`/`rot`, i.e. the
   * fold's `keyGen`/`keySeq`.
   *
   * Defaults to `prior`'s position, right only while sequence and derivation index still coincide: a
   * `rev` advances `s` and establishes no key, so after the first revoke of a generation the two part
   * company **and never rejoin**. Every rotate after a revoke needs this, not just the one directly
   * on it. Optional rather than required because {@link createRotate} verifies the key it reveals
   * against `prior`'s commitment and throws on disagreement — provably right where omitted, an error
   * (not an unfoldable event) where not. Take it from `KeyState.keyGen`/`keySeq`.
   */
  keyPosition?: { gen: number; seq: number }
}

export type CreateRotateParams = {
  seed: Uint8Array
  profile: number
  did: string
  prior: EventCommon
  options?: CreateRotateOptions
}

/**
 * A rotate reveals the keys the prior event pre-committed and commits the next set, signed by the
 * newly revealed keys (per KERI — what makes a stolen current key unable to rotate). Reproducible
 * from the seed alone unless it carries a seal or deny snapshot.
 *
 * **Throws rather than emitting an event the fold will reject.** The revealed key must be the one
 * `prior` committed in `n`, and `options.keyPosition` decides which key gets derived — so a wrong
 * position used to produce a well-formed, signed event no fold would accept. The two are checked
 * against each other here. When `prior` carries no commitment (a `rev`), `keyPosition` is required:
 * the default would derive a key one past the *revoke*, which nothing committed, and this is the one
 * case unverifiable from `prior` alone.
 */
export function createRotate({
  seed,
  profile,
  did,
  prior,
  options = {},
}: CreateRotateParams): SignedEvent<RotateEvent> {
  const gen = prior.g
  const seq = prior.s + 1
  // The commitment the revealed key must match, when `prior` carries one. An `icp`/`rot` does; a
  // `rev` and any hand-built prior of another shape does not.
  const commitment = (prior as { n?: unknown }).n
  const committed = isKeyList(commitment) && commitment.length > 0 ? commitment : undefined
  // The checks below only have an answer when this seed *is* the log's root — otherwise the
  // commitment was written by somebody else's key material and a mismatch says nothing. Refusing
  // there would stop this generator building a foreign rotate at all (which the conformance suite
  // legitimately does); the fold is the layer that rejects it.
  const root = didFromInception(inceptionEvent(seed, profile)) === did
  if (root && committed == null && options.keyPosition == null) {
    throw new Error(
      'createRotate: prior event pre-commits no key, so keyPosition is required — pass the fold`s ' +
        'KeyState.keyGen / keySeq for the position the last icp/rot established',
    )
  }
  // The key this rotate reveals is the one the last icp/rot committed, one past *its* position; the
  // agreement key lands at the same index so `KeyState.keyGen`/`keySeq` names it for a recipient
  // re-deriving from the seed. See `CreateRotateOptions.keyPosition` for why these diverge from `s`.
  const keyGen = options.keyPosition?.gen ?? gen
  const keySeq = (options.keyPosition?.seq ?? prior.s) + 1
  const current = deriveKeyPair(seed, authorityPath(profile, keyGen, keySeq), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, keyGen, keySeq + 1), 'EdDSA')
  const agreement = deriveKeyPair(seed, agreementPath(profile, keyGen, keySeq), 'X25519')

  if (root && committed != null) {
    // Exactly what `verifyRotate` checks, checked here where the caller can still act. Arity first:
    // this generator emits a single key, so a prior committing any other number has no rotate here.
    const revealed = encodeKey(current.publicKey, 'EdDSA')
    if (committed.length !== 1 || digestOf(revealed) !== committed[0]) {
      throw new Error(
        `createRotate: the key at (gen ${keyGen}, seq ${keySeq}) is not the one the prior event ` +
          'pre-committed — pass options.keyPosition naming where the last icp/rot established a ' +
          'key (the fold`s KeyState.keyGen / keySeq). A revoke advances `s` without establishing ' +
          'one, so `s` and the derivation index part company at the first revoke of a generation ' +
          'and stay apart.',
      )
    }
  }

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
    d: options.denySnapshot,
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
}

/**
 * Whether the members a rotate publishes into the folded state have the shape the fold will carry.
 * Shared by {@link verifyRotate} and {@link verifyReset}: both hand `k`/`n`/`d` to the next
 * `KeyState`, and a reset verifies against the recovery key not `k`, so without this it could publish
 * a key set of any shape.
 *
 * `r` is refused outright — the runtime half of removing it from {@link RotateEvent}. A member the
 * fold silently ignored would be the field-that-lies this removal is about: a reader seeing `r` on a
 * rotate would take the recovery key to have moved when nothing moved it.
 */
function isPublishedRotate(event: RotateEvent): boolean {
  return (
    isKeyList(event.k) &&
    isKeyList(event.n) &&
    isEnforcedThreshold(event.kt, event.k) &&
    isEnforcedThreshold(event.nt, event.n) &&
    // A seal is opaque but still a digest string on the wire (see `RotateEvent.a`); a non-string one
    // is a member a reader would have to guess at.
    (event.a == null || typeof event.a === 'string') &&
    (event as { r?: unknown }).r === undefined &&
    // The snapshot replaces the accumulated set, so the fold builds a `Set` from it: a scalar `d`
    // throws, a string `d` would silently become a set of characters.
    (event.d == null || isKeyList(event.d))
  )
}

/**
 * A rotate is valid when it chains to the prior digest, its revealed keys match the prior event's
 * pre-rotation commitment, and its signatures verify against those keys.
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
 * Anchored to the inception, not the log head: the recovery key lives on the root-retained
 * derivation branch and its digest is committed in the deterministic inception, so a restored
 * mnemonic can author one with no log knowledge or availability. Carries no options — no seal, `d`
 * always `[]` — so a reset is a pure function of `(seed, profile, gen)`, and two blind resets at one
 * generation produce identical bytes that resolve as idempotent re-derivation, not duplicity.
 *
 * The root need not know the current generation, only eventually exceed it (no attacker can author a
 * competing reset at any generation): a blind root starts at `gen = 1` and retries higher if it
 * learns of one — the cost is a round trip, never loss of control.
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
 * A reset verifies against the committed recovery digest, not the pre-rotation set. Both values it
 * needs — the anchor digest and the recovery commitment — come from the inception, the *only* place
 * either can: that is what lets a root holding nothing but its seed author one with no log
 * availability. If the commitment could move, the root would have to read the log to know which key
 * to sign with, and the one recovery path that survives losing the log would be gone.
 * `recoveryPath(profile)` carries no index for the same reason — one recovery key per profile, for
 * its lifetime. See {@link RotateEvent} for what was removed.
 */
export function verifyReset(signed: SignedEvent<RotateEvent>, inception: InceptionEvent): boolean {
  const { event, sigs } = signed
  if (event.t !== 'rot' || event.p !== digestOf(inception) || event.s !== 0 || event.g < 1) {
    return false
  }
  if (!isPublishedRotate(event)) {
    return false
  }
  // A reset carries an empty deny set and no seal (see {@link createReset}) — the idempotency the
  // branch selector relies on. Only the recovery-key holder can sign one, so this is not an
  // attacker's event; it is the rule that makes "blind reset" mean the same bytes for every holder of
  // the seed. Enforced here too so a reset carrying a non-empty `d` or a seal cannot fold as valid.
  if (event.a !== undefined || event.d == null || event.d.length !== 0) {
    return false
  }
  if (!Array.isArray(sigs) || sigs.length !== 1) {
    return false
  }
  if (!verifyAgreementKeys(event.ka)) {
    return false
  }
  // The recovery key is committed as a digest and unpublished until used, so a reset must carry the
  // revealed key on the envelope for the commitment to be checkable.
  const revealed = signed.recoveryKey
  if (revealed == null || digestOf(revealed) !== inception.r) {
    return false
  }
  return verifySignatures(event, sigs, [revealed])
}

/**
 * How a `rev` target names a **key** rather than a DID: `#<the multibase key exactly as it appears in
 * `k`>`, the same spelling a token's `kid` uses. One spelling for one thing — unambiguous against
 * `did:…` on sight, so a bare multibase string is not a second accepted encoding, any more than for
 * `kid`.
 */
export const KEY_TARGET_PREFIX = '#'

/** The deny-set spelling of `key` — what {@link createRevoke} takes as its target to deny it. */
export function keyTarget(key: string): string {
  return `${KEY_TARGET_PREFIX}${key}`
}

/**
 * The key a `rev` target names, or `null` when it names a DID instead. Total on any string: a target
 * of neither form lands in the deny set as the opaque identifier it is. The body is not validated
 * against multibase — a `#` naming nothing denies nothing, exactly as a `did:` naming nobody does,
 * and rejecting it would only add a way for a well-formed log to stop folding.
 */
export function keyFromTarget(target: string): string | null {
  return target.startsWith(KEY_TARGET_PREFIX) ? target.slice(KEY_TARGET_PREFIX.length) : null
}

export type RevokeEvent = EventCommon & {
  t: 'rev'
  /**
   * What to deny, in one of two spellings, never a capability `jti`.
   *
   * A **DID** (`did:…`) denies a holder: no capability whose `aud` is that DID is valid from this
   * position onward — one entry covers a device's life. A **key** ({@link keyTarget}) denies a
   * signer: nothing this profile signed with that key verifies from this position onward, and it
   * names a key of *this* profile (the deny set is the subject's own).
   *
   * One field carries both because they are enforced at opposite ends of the same set: the DID form
   * by `@kokuin/capability` against a capability's `aud`, the key form by the resolver against the
   * key a `kid` selects. Neither spelling can be mistaken for the other.
   */
  x: string
  /** A serialized capability authorising a non-authority signer. Verified in the fold. */
  cap?: string
}

export type CreateRevokeParams = {
  seed: Uint8Array
  profile: number
  did: string
  prior: EventCommon
  target: string
  keyPosition: { gen: number; seq: number }
  /** A serialized capability authorising this signer, when the signer is not an authority key. */
  cap?: string
}

/**
 * Revoke a DID or a key — see {@link RevokeEvent.x} for the two spellings.
 *
 * Naming the device DID rather than a `jti` makes this one entry per device for its life — covering
 * capabilities the verifier has never seen and future re-mints, where per-`jti` revocation would grow
 * with every renewal. A key target retires a leaked key for material it *already* signed: `rotate`
 * only retires it for new issuance (`resolve` is head-only), but already-issued material verifies
 * through `resolveHistoric`, which survives a rotate by design, so a thief holding a rotated-away key
 * could still mint one that verified. Retirement is therefore explicit, keeping the promise that a
 * routine rotate does not invalidate already-issued material intact.
 *
 * **A key the profile currently publishes cannot be denied** — the fold rejects it (see the `rev`
 * branch of `stepEvent`). Rotate first, then deny the key the rotate retired.
 *
 * `prior` answers "next sequence, what to chain to"; `keyPosition` separately answers "where the
 * active authority key lives". They coincide only for an `icp`/`rot` prior — a `rev` establishes no
 * key, so a revoke on a revoke still points at the last `icp`/`rot` position.
 */
export function createRevoke({
  seed,
  profile,
  did,
  prior,
  target,
  keyPosition,
  cap,
}: CreateRevokeParams): SignedEvent<RevokeEvent> {
  const current = deriveKeyPair(
    seed,
    authorityPath(profile, keyPosition.gen, keyPosition.seq),
    'EdDSA',
  )
  return createRevokeWithKey({ privateKey: current.privateKey, did, prior, target, cap })
}

export type CreateRevokeOptions = {
  /** A serialized capability authorising this signer, when the signer is not an authority key. */
  cap?: string
}

export type CreateRevokeWithKeyParams = {
  privateKey: Uint8Array
  did: string
  prior: EventCommon
  target: string
  /** A serialized capability authorising this signer, when the signer is not an authority key. */
  cap?: string
}

/**
 * Revoke a DID, signing with an Ed25519 key the caller already holds rather than deriving one from
 * the profile seed.
 *
 * The builder for the actor a capability-authorised revoke exists for: a device holding a management
 * capability, which by design never receives the profile sub-seed. `createRevoke` can only sign as
 * the profile itself, so without this the feature had no API but re-implementing the signing
 * convention per consumer — the duplication `createControllerCapabilityVerifier` prevents on the
 * verifying side.
 *
 * The key is the audience key the capability pins in `cnf`, and the fold checks the event's signature
 * against exactly that, so the two must match. Ed25519 only. Takes the private key rather than an
 * identity because no identity type here signs raw bytes — a `KeyStore` entry hands back exactly this
 * shape. Byte-identical to {@link createRevoke} given the same key; no `keyPosition`, which exists
 * only to derive a key from a seed.
 */
export function createRevokeWithKey({
  privateKey,
  did,
  prior,
  target,
  cap,
}: CreateRevokeWithKeyParams): SignedEvent<RevokeEvent> {
  const event: RevokeEvent = {
    v: 1,
    t: 'rev',
    i: did,
    g: prior.g,
    s: prior.s + 1,
    p: digestOf(prior),
    crit: true,
    x: target,
    cap,
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
