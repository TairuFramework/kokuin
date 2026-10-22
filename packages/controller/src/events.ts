import type { DIDString } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlnopad } from '@scure/base'

import { canonicalBytes, digestOf, isCanonicalizable } from './canonical.js'
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from './derivation.js'
import type { EpochEventCommon } from './epoch-events.js'
import { encodeKey, tryDecodeKey } from './keys.js'

export const DID_PREFIX = 'did:kokuin:'

/**
 * The root chain's event types, and only those: it holds the key-establishing events. Management
 * actions — member adds, renewals, removals and revokes — live in the epoch a chain event opens,
 * never on the chain. A chain entry of any other `t`, a `rev` from an older log included, takes the
 * fold's unknown-type path, so a critical one fails the fold closed.
 */
export type EventType = 'icp' | 'rot'

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

/**
 * Generic over both tiers: a root-chain event and an epoch event share the envelope and signatures
 * over canonical bytes, and nothing else.
 */
export type SignedEvent<E extends EventCommon | EpochEventCommon = EventCommon> = {
  event: E
  /** base64url ed25519 signatures over the canonical event bytes, positional against `event.k`. */
  sigs: Array<string>
  /**
   * The revealed recovery public key, present only on a reset. The recovery key is committed as a
   * digest and unpublished until used, so a reset must reveal it for the commitment to be checkable.
   */
  recoveryKey?: string
}

export function signEvent(
  event: EventCommon | EpochEventCommon,
  privateKeys: Array<Uint8Array>,
): Array<string> {
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
export function isKeyList(value: unknown): value is Array<string> {
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
  event: EventCommon | EpochEventCommon,
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

/**
 * One management member as a snapshot carries it: the DID it acts as, the Ed25519 key that DID is
 * pinned to (in the spelling `k` uses), the digest of the `add` that admitted it — its incarnation,
 * which renewals and removals name — and its lease end in unix seconds.
 *
 * The fold never reads `lease` against a clock: it bounds the grants the member mints, nothing on the
 * log. Only a removal ends a member's log authority.
 */
export type MemberEntry = { did: string; key: string; add: string; lease: number }

/**
 * The whole management state a root-chain event leaves behind: the member set and the deny set. The
 * state after the event **is** this snapshot — nothing before it contributes — so it is root's
 * chosen replacement state, not a proven merge of everything that happened before it.
 */
export type StateSnapshot = { members: Array<MemberEntry>; deny: Array<string> }

/**
 * The shape of one snapshot member, nothing more: whether the DID carries the key, whether the key
 * is Ed25519, and whether it collides with a root key are rules over the whole snapshot and its chain,
 * checked by the fold. `lease` must be a non-negative safe integer — unix seconds — because grants
 * compare `exp` against it, and a fraction, a negative or an unsafe integer has no single reading.
 */
export function isMemberEntry(value: unknown): value is MemberEntry {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  const entry = value as Record<string, unknown>
  return (
    typeof entry.did === 'string' &&
    typeof entry.key === 'string' &&
    typeof entry.add === 'string' &&
    typeof entry.lease === 'number' &&
    Number.isSafeInteger(entry.lease) &&
    entry.lease >= 0
  )
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
  /**
   * Member half of the state snapshot — see {@link StateSnapshot}. Required, with `d`, on every
   * rotate that is not a reset: every rotate is a settlement. A reset carries both or neither.
   */
  m?: Array<MemberEntry>
  /** Deny half of the state snapshot. Replaces the set the prior state held outright. */
  d?: Array<string>
}

export type CreateRotateParams = {
  seed: Uint8Array
  profile: number
  did: string
  prior: EventCommon
  /**
   * The complete state this rotate leaves behind — **a replacement, not an addition**. The state
   * after a rotate is its snapshot and nothing before it, so a caller writing one deny entry meaning
   * "also deny this" silently drops every other entry and every member — un-revoking devices and
   * dismissing the management tier — with nothing in the log saying anything was lost. Build it from
   * the folded state with {@link snapshotOf}, which also carries every member forward.
   *
   * Required: there is no "carry the prior state forward" rotate, because the prior state may hold
   * epoch effects a verifier holding only the chain cannot reproduce. Two rules the fold enforces
   * here: a member may not pin a key on, or committed by, this generation's root chain; and a
   * retired-key denial an earlier rotate in the generation carried may not be dropped.
   */
  snapshot: StateSnapshot
  /** Seal: an anchored external digest — see {@link RotateEvent.a}. */
  seal?: string
}

/**
 * A rotate reveals the keys the prior event pre-committed and commits the next set, signed by the
 * newly revealed keys (per KERI — what makes a stolen current key unable to rotate). Reproducible
 * from the seed and the snapshot unless it carries a seal.
 *
 * The root chain holds only key-establishing events, so a rotate's sequence and its derivation index
 * are the same number: the key it reveals sits one past `prior`'s position.
 *
 * **Throws rather than emitting an event the fold will reject.** The revealed key must be the one
 * `prior` committed in `n`, which a prior not built from this chain's own events need not be.
 */
export function createRotate({
  seed,
  profile,
  did,
  prior,
  snapshot,
  seal,
}: CreateRotateParams): SignedEvent<RotateEvent> {
  const gen = prior.g
  const seq = prior.s + 1
  // The commitment the revealed key must match. Every `icp`/`rot` carries one; a hand-built prior of
  // another shape does not.
  const commitment = (prior as { n?: unknown }).n
  const committed = isKeyList(commitment) && commitment.length > 0 ? commitment : undefined
  // The checks below only have an answer when this seed *is* the log's root — otherwise the
  // commitment was written by somebody else's key material and a mismatch says nothing. Refusing
  // there would stop this generator building a foreign rotate at all (which the conformance suite
  // legitimately does); the fold is the layer that rejects it.
  const root = didFromInception(inceptionEvent(seed, profile)) === did
  if (root && committed == null) {
    throw new Error('createRotate: prior event pre-commits no key, so there is nothing to reveal')
  }
  // The agreement key lands at the same index as the authority key, so `KeyState.keyGen`/`keySeq`
  // names both for a recipient re-deriving from the seed.
  const current = deriveKeyPair(seed, authorityPath(profile, gen, seq), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, gen, seq + 1), 'EdDSA')
  const agreement = deriveKeyPair(seed, agreementPath(profile, gen, seq), 'X25519')

  if (root && committed != null) {
    // Exactly what `verifyRotate` checks, checked here where the caller can still act. Arity first:
    // this generator emits a single key, so a prior committing any other number has no rotate here.
    const revealed = encodeKey(current.publicKey, 'EdDSA')
    if (committed.length !== 1 || digestOf(revealed) !== committed[0]) {
      throw new Error(
        `createRotate: the key at (gen ${gen}, seq ${seq}) is not the one the prior event ` +
          'pre-committed — the prior is not an event of this log',
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
    a: seal,
    m: snapshot.members,
    d: snapshot.deny,
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
}

/**
 * Whether the members a rotate publishes into the folded state have the shape the fold will carry.
 * Shared by {@link verifyRotate} and {@link verifyReset}: both hand `k`/`n` to the next `KeyState`,
 * and a reset verifies against the recovery key not `k`, so without this it could publish a key set
 * of any shape.
 *
 * The snapshot (`m`/`d`) is not judged here: whether it is well formed, disjoint from the root keys
 * and keeps the generation's retired keys depends on the chain it lands on, so the fold judges it
 * with a reason of its own (see `validateSnapshot`). These verifiers answer only whether the event
 * is signed by, and chains to, what it claims.
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
    (event as { r?: unknown }).r === undefined
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
 * mnemonic can author one with no log knowledge or availability.
 *
 * **Blind** (no `snapshot`): no seal, `d: []` and no `m`, so a blind reset is a pure function of
 * `(seed, profile, gen)` and two blind resets at one generation produce identical bytes that resolve
 * as idempotent re-derivation, not duplicity. The new epoch starts empty and root re-adds members.
 * This is the path for a root that does not know the log's state.
 *
 * **With a snapshot**: the same reset carries the member and deny sets, so one recovery-key
 * signature is the whole recovery. Two resets at one generation with different bytes are then
 * duplicity — which only the recovery-key holder can cause, and a reset at a higher generation
 * resolves. Members keep their `add` references, but every grant names its generation, so every
 * grant minted under the prior one still dies. The snapshot is checked against the **new**
 * generation's keys, and no retired-key denial of the old one need carry over.
 *
 * The root need not know the current generation, only eventually exceed it (no attacker can author a
 * competing reset at any generation): a blind root starts at `gen = 1` and retries higher if it
 * learns of one — the cost is a round trip, never loss of control.
 */
export function createReset(
  seed: Uint8Array,
  profile: number,
  gen: number,
  snapshot?: StateSnapshot,
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
  }
  if (snapshot == null || (snapshot.members.length === 0 && snapshot.deny.length === 0)) {
    // A blind reset clears the deny set: every capability under the prior generation is gone anyway.
    // Written as `d: []` rather than omitted so a blind reset keeps the bytes it always had. An empty
    // snapshot is the same state and is written the same way, so a retry with one is byte-identical
    // to a blind reset rather than a second encoding of it.
    event.d = []
  } else {
    event.m = snapshot.members
    event.d = snapshot.deny
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
  // A reset carries no seal, and either a whole snapshot (`m` and `d` together) or none. Without `m`
  // it is blind, and a blind reset's `d` is exactly the `[]` {@link createReset} writes: one encoding,
  // so "blind reset" means the same bytes for every holder of the seed — the idempotency the branch
  // selector relies on. For the same reason an empty snapshot (`m: []` with `d: []`) is refused: it is
  // the blind state spelled a second way. Only the recovery-key holder can sign one, so this is not an
  // attacker's event; it is the rule that keeps one state from having two resets at a generation,
  // and half a snapshot (`d` with no `m`, or `m` with no `d`) from folding as a reset that silently
  // dismissed every member or cleared every denial. The snapshot's contents are the fold's to judge,
  // against the new generation's keys.
  if (event.a !== undefined) {
    return false
  }
  const emptyDeny = isKeyList(event.d) && event.d.length === 0
  if (event.m == null ? !emptyDeny : event.d == null) {
    return false
  }
  if (Array.isArray(event.m) && event.m.length === 0 && emptyDeny) {
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
 * How a deny entry names a **key** rather than a DID: `#<the multibase key exactly as it appears in
 * `k`>`, the same spelling a token's `kid` uses. One spelling for one thing — unambiguous against
 * `did:…` on sight, so a bare multibase string is not a second accepted encoding, any more than for
 * `kid`.
 */
export const KEY_TARGET_PREFIX = '#'

/** The deny-set spelling of `key` — what a snapshot's `d` carries to deny it. */
export function keyTarget(key: string): string {
  return `${KEY_TARGET_PREFIX}${key}`
}

/**
 * The key a deny entry names, or `null` when it names a DID instead. Total on any string: an entry of
 * neither form lands in the deny set as the opaque identifier it is. The body is not validated
 * against multibase — a `#` naming nothing denies nothing, exactly as a `did:` naming nobody does,
 * and rejecting it would only add a way for a well-formed log to stop folding.
 */
export function keyFromTarget(target: string): string | null {
  return target.startsWith(KEY_TARGET_PREFIX) ? target.slice(KEY_TARGET_PREFIX.length) : null
}
