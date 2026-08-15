import type { DIDString, ResolvedSigningKey } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlnopad } from '@scure/base'

import { canonicalBytes, digestOf, isCanonicalizable } from './canonical.js'
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
  /**
   * Signing threshold: how many of `k` must sign. **Must equal `k.length`** — see
   * {@link isEnforcedThreshold}.
   */
  kt: number
  /**
   * Rotation threshold: how many of the keys `n` commits must sign the next rotate. **Must equal
   * `n.length`** — see {@link isEnforcedThreshold}.
   */
  nt: number
  /**
   * Digest of the recovery key. Root-retained, and **immutable for the life of the DID** — the
   * only event that can carry one is this one, and this one is the DID.
   *
   * A rotate used to carry an optional `r` documented as a recovery-commitment update. Nothing
   * read it: `verifyReset` checked the inception's value regardless, so the original recovery key
   * could never be retired while `KeyState.recovery` reported a different one. It is gone, and a
   * rotate carrying one is refused rather than ignored — see {@link RotateEvent}.
   */
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
 * Whether a published threshold agrees with what the fold actually enforces.
 *
 * `kt` and `nt` were published, digested into the event — and therefore into the DID, for an
 * inception — declared in the type with real semantics, and read by nothing. The fold enforces
 * n-of-n and only n-of-n: {@link verifySignatures} requires one valid signature per published key,
 * and {@link verifyRotate} requires every key the prior event committed to be revealed and to sign.
 * So the only threshold these fields can truthfully carry is the size of the set they govern, and
 * anything else — `99`, `0`, `-5`, `"banana"`, `null`, an absent member — is an event whose own
 * declaration contradicts the rule it will be judged by.
 *
 * That is a malformed event rather than a policy this package might one day honour. Inside a wire
 * format fixed by the DID derivation, a field nothing reads is a trap for the next reader; a field
 * pinned to what is enforced is a fact. If quorum ever lands, the check moves with the enforcement
 * and every log written until then still means what it said.
 *
 * The comparison is `===` against the length, so a string `"1"` fails: the value is wire data, and
 * a threshold that has to be coerced to be read is not a threshold.
 */
function isEnforcedThreshold(threshold: unknown, keys: Array<string>): boolean {
  return threshold === keys.length
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

/**
 * Total: a malformed signature or key yields false rather than throwing.
 *
 * That includes an event body the canonicalizer refuses. This function is exported and documented
 * total, and `canonicalBytes` below is a throw for a body carrying a non-finite number or nesting
 * past `MAX_CANONICAL_DEPTH` — both of which arrive from `JSON.parse`. The fold's envelope guard
 * already rejects such a body one layer out, so this check is unreachable through `foldLog`; it
 * stays because a direct caller reaches this function with a parsed body and nothing else, and
 * because "total" has to be true of the export rather than of one path into it.
 *
 * `false` is the honest answer: a body with no canonical encoding has no bytes for a signature to
 * be over, so no signature verifies against it.
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
 * Total: a malformed signature, an event body with no canonical encoding, or an algorithm this
 * log's events cannot be signed with all yield `false`. Only EdDSA is accepted, because that is all
 * {@link signEvent} produces — an ES256 audience therefore cannot author a revoke, which fails
 * closed and is the honest answer until events grow a second signature algorithm.
 */
export function verifyEventSignedBy(signed: SignedEvent, key: ResolvedSigningKey): boolean {
  // `sigs` needs no array check of its own, and this is the rule the whole file applies: **a guard
  // stays when the value it inspects can reach it in the shape it rejects, even if no test can
  // kill it; it is removed only when that value cannot reach it at all, and the unreachability is
  // pinned by a test.** Both arms of the check below are unkillable under it and stay: a
  // non-EdDSA key would fail `ed25519.verify` inside the `catch` anyway, and `[].some()` is
  // already `false`. They state what this function accepts rather than relying on what the code
  // beneath them happens to do. Here it cannot: this function is unexported, the fold is its only caller,
  // and `isSignedEventShape` has already established that `sigs` is an array of strings —
  // `deleted-guards.test.ts` walks every non-array `sigs` shape to the envelope guard and shows it
  // stopping there. "Unkillable" alone is not the test: several guards below are unkillable and
  // stay, because the shapes they reject do arrive from `JSON.parse` and only reach a rejection at
  // all because something checks.
  if (key.alg !== 'EdDSA' || signed.sigs.length === 0) {
    return false
  }
  // Unreachable through the fold — `isSignedEventShape` has already established that this body can
  // be canonicalized — and kept by the rule stated above: the value it inspects reaches it in the
  // shape it rejects whenever a caller reaches this function with a parsed body directly, and
  // `canonicalBytes` is a throw rather than an answer for one.
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
 * Deterministic inception. Contains only seed-derived and canonical material — no timestamp, no
 * nonce, no user label — so its hash, and therefore the DID, is a pure function of the seed and
 * the profile index.
 *
 * A user label must never be added here. The DID depends on every byte, so a mistyped label on
 * recovery would reproduce a different DID.
 */
export function createInception(seed: Uint8Array, profile: number): SignedEvent<InceptionEvent> {
  const event = inceptionEvent(seed, profile)
  const current = deriveKeyPair(seed, authorityPath(profile, 0, 0), 'EdDSA')
  return { event, sigs: signEvent(event, [current.privateKey]) }
}

/**
 * The inception body alone, unsigned.
 *
 * Split out because {@link createRotate} needs the DID this seed and profile index produce in order
 * to know whether it is the log's root, and signing an inception it will throw away to find out is
 * the one expensive step in building one.
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
  // An inception is self-certifying, so *any* body an attacker writes is a valid log for the DID it
  // hashes to — which is exactly why the thresholds it publishes have to mean something.
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
  /**
   * Key agreement public keys — an OR set, never combined. Carries no pre-rotation commitment.
   */
  ka: Array<string>
  /** Digests of the next public keys — pre-rotation. */
  n: Array<string>
  /** Signing threshold: how many of `k` must sign. **Must equal `k.length`.** */
  kt: number
  /** Rotation threshold: how many of `n` must sign the next rotate. **Must equal `n.length`.** */
  nt: number
  /**
   * Seal: an anchored external digest, pinning a high-value grant to this log position.
   *
   * Opaque to the fold **by design**, and that is the difference between this and the `r` that was
   * removed: a seal's whole job is to be an anchor whose meaning belongs to whatever produced it,
   * and nothing in the key state can contradict it. What the fold owes it is that it cannot ride in
   * as something other than a digest string — a non-string `a` is a malformed event, checked in
   * {@link isPublishedRotate} — so a reader that finds one can read it as one.
   *
   * Not surfaced in `KeyState`: it belongs to a position, not to the key state, and the events are
   * in the caller's hands already.
   */
  a?: string
  /** Deny-set snapshot. Replaces the accumulated set, pruning it. */
  d?: Array<string>
}

export type CreateRotateOptions = {
  seal?: string
  /**
   * The complete deny set this rotate leaves behind — **a replacement, not an addition**.
   *
   * Named for what it is because the fold does exactly what it says: `d` present replaces the
   * accumulated set, `d` absent carries it forward. A caller who writes one entry meaning "also deny
   * this" silently drops every entry the log had accumulated, which un-revokes the devices *and*
   * un-retires the leaked keys the profile had denied — no error, no event, and nothing in the
   * resulting log that says anything was lost. That is the whole reason to prune from a rotate at
   * all (nothing else can), and the whole reason it must be spelled loudly.
   *
   * Build it from the folded state rather than by hand: {@link pruneDenySet} takes the current
   * `KeyState` and the entries to drop and returns the rest. `[]` is the deliberate "clear
   * everything" — what a cold rotate does to recover from a management tier gone bad.
   *
   * A rotate cannot establish a key its own snapshot denies; the fold refuses such an event rather
   * than publishing a head whose keys resolve to nothing.
   */
  denySnapshot?: Array<string>
  /**
   * Where the currently-active authority key lives — the position of the last `icp`/`rot`, which
   * is the fold's `keyGen`/`keySeq`.
   *
   * Defaults to `prior`'s own position, which is right only while the log's sequence and its
   * derivation index still coincide: a `rev` advances `s` and establishes no key (Amendment A), so
   * after the first revoke in a generation the two part company **and never rejoin**. It is not
   * enough to pass this for the rotate that sits directly on a revoke — every rotate after one
   * needs it too, because `s` stays ahead of the derivation index for the rest of the generation.
   *
   * Left optional rather than made required, and checked instead: {@link createRotate} verifies the
   * key it is about to reveal against `prior`'s own pre-rotation commitment and throws when they
   * disagree. That covers the wrong default and a wrong value alike, and it covers them for exactly
   * the events the fold would reject — so the position is optional where it is provably right, and
   * an error rather than an unfoldable event where it is not. Take it from `KeyState.keyGen` and
   * `KeyState.keySeq`; those are the fold's own answer.
   */
  keyPosition?: { gen: number; seq: number }
}

/**
 * A rotate reveals the keys the prior event pre-committed and commits the next set. Signed by the
 * newly revealed keys, per KERI, which is what makes a stolen current key unable to rotate.
 *
 * Reproducible from the seed alone unless it carries a seal or a deny snapshot.
 *
 * **Throws rather than emitting an event the fold will reject.** The key a rotate reveals has to be
 * the one `prior` pre-committed in `n`, and `options.keyPosition` is what decides which key gets
 * derived — so a wrong or defaulted-wrong position used to produce a well-formed, correctly signed
 * event that no fold would ever accept, with nothing said at emit time. The two are checked against
 * each other here: `prior.n` is the commitment and it is right there in the argument.
 *
 * When `prior` carries no commitment to check against — a `rev`, which establishes no key —
 * `keyPosition` is required, because there the default is provably wrong: it would derive a key one
 * past the *revoke*, which nothing ever pre-committed. That case cannot be verified from `prior`
 * alone, so it is the one place the caller is trusted, and `KeyState.keyGen`/`keySeq` is where the
 * value comes from.
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
  // The pre-rotation commitment the revealed key must match, when `prior` carries one. An `icp` and
  // a `rot` do; a `rev` does not, and neither does a hand-built prior of any other shape.
  const commitment = (prior as { n?: unknown }).n
  const committed = isKeyList(commitment) && commitment.length > 0 ? commitment : undefined
  // Every check below asks "will my own log reject this event", and that question only has an
  // answer when this seed *is* the log's root. When it is not — a forgery built for a test, a
  // hand-mutated prior, a profile this seed never inceptioned — a mismatch says nothing about the
  // position, because the commitment was written by somebody else's key material entirely. Refusing
  // there would turn this generator into something that cannot build a foreign rotate at all, which
  // is a thing the conformance suite legitimately does; the fold is the layer that rejects it.
  const root = didFromInception(inceptionEvent(seed, profile)) === did
  if (root && committed == null && options.keyPosition == null) {
    throw new Error(
      'createRotate: prior event pre-commits no key, so keyPosition is required — pass the fold`s ' +
        'KeyState.keyGen / keySeq for the position the last icp/rot established',
    )
  }
  // The log position and the derivation position are the same thing only until the first revoke —
  // see `CreateRotateOptions.keyPosition`. The key this rotate reveals is the one the last icp/rot
  // pre-committed, which sits one past *its* position, and the agreement key lands at the same
  // index so that `KeyState.keyGen`/`keySeq` names it for a recipient re-deriving from the seed.
  const keyGen = options.keyPosition?.gen ?? gen
  const keySeq = (options.keyPosition?.seq ?? prior.s) + 1
  const current = deriveKeyPair(seed, authorityPath(profile, keyGen, keySeq), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, keyGen, keySeq + 1), 'EdDSA')
  const agreement = deriveKeyPair(seed, agreementPath(profile, keyGen, keySeq), 'X25519')

  if (root && committed != null) {
    // Exactly what `verifyRotate` will check, checked here where the caller can still act on it.
    // The arity first: this generator emits a single key, so a prior committing any other number
    // of them has no rotate this function can produce.
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
 *
 * Shared by {@link verifyRotate} and {@link verifyReset}: the two verify different signatures over
 * the same event body, and both hand `k`, `n` and `d` straight to the next `KeyState`. A reset
 * in particular never verifies against `k` — it verifies against the revealed recovery key — so
 * without this it is the one event that can publish a key set of any shape at all.
 *
 * `r` is refused outright here, which is the runtime half of removing it from {@link RotateEvent}.
 * The type stops this package writing one; only a check stops a peer from putting one on the wire,
 * and a member the fold silently ignores is exactly the field-that-lies this removal is about — a
 * reader seeing `r` on a rotate would take the recovery key to have moved when nothing moved it.
 */
function isPublishedRotate(event: RotateEvent): boolean {
  return (
    isKeyList(event.k) &&
    isKeyList(event.n) &&
    isEnforcedThreshold(event.kt, event.k) &&
    isEnforcedThreshold(event.nt, event.n) &&
    // A seal is opaque to the fold, but it is still a digest string on the wire — see
    // `RotateEvent.a`. A non-string one is a member a reader would have to guess at.
    (event.a == null || typeof event.a === 'string') &&
    (event as { r?: unknown }).r === undefined &&
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
 *
 * The inception is the *only* place either value can come from, and that is a property rather than
 * a simplification. A reset anchors to the inception so a root holding nothing but its seed can
 * author one with no log knowledge and no log availability; if the recovery commitment could be
 * moved by a later event, the root would have to read the log to find out which key to sign with,
 * and the one recovery path that survives losing the log would be gone. `recoveryPath(profile)`
 * carries no index for the same reason — there is one recovery key per profile, for its lifetime.
 * See {@link RotateEvent} for what was removed and why.
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

/**
 * How a `rev` target names a **key** rather than a DID: `#<the multibase key exactly as it appears
 * in `k`>`, which is the same spelling a token's `kid` uses for the same key.
 *
 * One spelling for one thing. A `kid` already names a key this way, the form is unambiguous against
 * `did:…` on sight, and both the fragment and the deny set are wire-visible and effectively
 * permanent — so a bare multibase string is not a second accepted encoding here any more than it is
 * for `kid`.
 */
export const KEY_TARGET_PREFIX = '#'

/** The deny-set spelling of `key` — what {@link createRevoke} takes as its target to deny it. */
export function keyTarget(key: string): string {
  return `${KEY_TARGET_PREFIX}${key}`
}

/**
 * The key a `rev` target names, or `null` when the target names a DID instead.
 *
 * Total on any string: a target that is neither form is simply not a key target, and lands in the
 * deny set as the opaque identifier it is. The fold does not validate the body against multibase —
 * a `#` followed by something no key set contains denies nothing, exactly as a `did:` naming nobody
 * denies nobody, and rejecting it would only add a way for a well-formed log to stop folding.
 */
export function keyFromTarget(target: string): string | null {
  return target.startsWith(KEY_TARGET_PREFIX) ? target.slice(KEY_TARGET_PREFIX.length) : null
}

export type RevokeEvent = EventCommon & {
  t: 'rev'
  /**
   * What to deny, in one of two spellings, never a capability `jti`.
   *
   * A **DID** — `did:…` — denies a holder: no capability whose `aud` is that DID is valid from this
   * position onward. A device DID, and one entry covers that device's life.
   *
   * A **key** — {@link keyTarget}, i.e. `#<the multibase key exactly as it appears in `k`>` — denies
   * a signer: nothing this profile signed with that key verifies from this position onward. It
   * names a key of *this* profile, since the deny set is the subject's own; denying somebody else
   * is what the DID form is for.
   *
   * The two are enforced at opposite ends of the same set, which is why one field carries both: the
   * DID form is read by `@kokuin/capability` against a capability's `aud`, and the key form by the
   * resolver against the key a `kid` selects. Neither spelling can be mistaken for the other.
   */
  x: string
  /** A serialized capability authorising a non-authority signer. Verified in the fold. */
  cap?: string
}

/**
 * Revoke a DID or a key — see {@link RevokeEvent.x} for the two spellings and what each denies.
 *
 * Naming the device DID rather than a `jti` makes this one entry per device for that device's
 * life — it covers capabilities the verifier has never seen and covers future re-mints, where
 * per-`jti` revocation would grow with every renewal.
 *
 * A key target is what retires a leaked key for material it already signed. `rotate` retires it for
 * *new* issuance — `resolve` is head-only — but already-issued capabilities and revocation records
 * are verified through `resolveHistoric`, which by design survives a rotate, so a thief holding a
 * rotated-away key could still mint one that verified. Retirement is therefore explicit rather than
 * a side effect of rotation: the design's promise that a routine rotate does not invalidate
 * already-issued material is load-bearing and stays intact.
 *
 * **A key the profile currently publishes cannot be denied** — the fold rejects such an event; see
 * the `rev` branch of `stepEvent`. Rotate first, then deny the key the rotate retired.
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
