import { decodeMultibase, encodeMultibase } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlnopad } from '@scure/base'

import { canonicalBytes, digestOf } from './canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from './derivation.js'

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
  /** Current public keys, multibase-encoded. */
  k: Array<string>
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

// Aliases of `@kokuin/token`'s multibase codec — kept under domain-specific names so callers say
// "this is a public key", not "this is a multibase string". Do not re-implement: `canonical.ts`
// already imports the same codec for digests, and a second implementation would only invite drift.
export function encodeKey(publicKey: Uint8Array): string {
  return encodeMultibase(publicKey)
}

export function decodeKey(value: string): Uint8Array {
  return decodeMultibase(value)
}

export function signEvent(event: EventCommon, privateKeys: Array<Uint8Array>): Array<string> {
  const bytes = canonicalBytes(event)
  return privateKeys.map((key) => base64urlnopad.encode(ed25519.sign(bytes, key)))
}

/** Total: a malformed signature or key yields false rather than throwing. */
export function verifySignatures(
  event: EventCommon,
  sigs: Array<string>,
  keys: Array<string>,
): boolean {
  if (sigs.length !== keys.length || sigs.length === 0) {
    return false
  }
  const bytes = canonicalBytes(event)
  for (let i = 0; i < sigs.length; i++) {
    try {
      if (!ed25519.verify(base64urlnopad.decode(sigs[i]), bytes, decodeKey(keys[i]))) {
        return false
      }
    } catch {
      return false
    }
  }
  return true
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

  const event: InceptionEvent = {
    v: 1,
    t: 'icp',
    g: 0,
    s: 0,
    crit: true,
    k: [encodeKey(current.publicKey)],
    n: [digestOf(encodeKey(next.publicKey))],
    kt: 1,
    nt: 1,
    r: digestOf(encodeKey(recovery.publicKey)),
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
}

export function didFromInception(event: InceptionEvent): string {
  return `${DID_PREFIX}${digestOf(event)}`
}

export function verifyInception(signed: SignedEvent<InceptionEvent>, did: string): boolean {
  if (signed.event.t !== 'icp' || signed.event.i !== undefined) {
    return false
  }
  if (didFromInception(signed.event) !== did) {
    return false
  }
  return verifySignatures(signed.event, signed.sigs, signed.event.k)
}

export type RotateEvent = EventCommon & {
  t: 'rot'
  /** Keys the prior event pre-committed, now revealed, multibase-encoded. */
  k: Array<string>
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
  const current = deriveKeyPair(seed, authorityPath(profile, gen, seq), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, gen, seq + 1), 'EdDSA')

  const event: RotateEvent = {
    v: 1,
    t: 'rot',
    i: did,
    g: gen,
    s: seq,
    p: digestOf(prior),
    crit: true,
    k: [encodeKey(current.publicKey)],
    n: [digestOf(encodeKey(next.publicKey))],
    kt: 1,
    nt: 1,
    a: options.seal,
    d: options.deny,
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
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
  if (event.k.length !== prior.n.length) {
    return false
  }
  for (let i = 0; i < event.k.length; i++) {
    if (digestOf(event.k[i]) !== prior.n[i]) {
      return false
    }
  }
  return verifySignatures(event, sigs, event.k)
}

/**
 * A reset: a rotate signed by the recovery key that increments the generation and discards
 * everything under the prior one, including every capability minted there.
 *
 * The recovery key lives on the root-retained derivation branch and its digest is committed in
 * the deterministic inception, so a restored mnemonic can always author one with no log at all.
 */
export function createReset(
  seed: Uint8Array,
  profile: number,
  did: string,
  prior: EventCommon,
  options: CreateRotateOptions = {},
): SignedEvent<RotateEvent> {
  const gen = prior.g + 1
  const current = deriveKeyPair(seed, authorityPath(profile, gen, 0), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, gen, 1), 'EdDSA')
  const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')

  const event: RotateEvent = {
    v: 1,
    t: 'rot',
    i: did,
    g: gen,
    s: 0,
    p: digestOf(prior),
    crit: true,
    k: [encodeKey(current.publicKey)],
    n: [digestOf(encodeKey(next.publicKey))],
    kt: 1,
    nt: 1,
    a: options.seal,
    // A reset clears the deny set: every capability under the prior generation is gone anyway.
    d: options.deny ?? [],
  }

  return {
    event,
    sigs: signEvent(event, [recovery.privateKey]),
    recoveryKey: encodeKey(recovery.publicKey),
  }
}

/** A reset verifies against the committed recovery digest, not against the pre-rotation set. */
export function verifyReset(
  signed: SignedEvent<RotateEvent>,
  prior: { digest: string; r: string },
): boolean {
  const { event, sigs } = signed
  if (event.t !== 'rot' || event.p !== prior.digest || event.s !== 0) {
    return false
  }
  if (sigs.length !== 1) {
    return false
  }
  // The recovery key is committed as a digest in the prior event and is not published until it is
  // used, so a reset must carry the revealed key on the signed envelope for the commitment to be
  // checkable.
  const revealed = signed.recoveryKey
  if (revealed == null || digestOf(revealed) !== prior.r) {
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
  options: { cap?: string } = {},
): SignedEvent<RevokeEvent> {
  const current = deriveKeyPair(
    seed,
    authorityPath(profile, keyPosition.gen, keyPosition.seq),
    'EdDSA',
  )

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

  return { event, sigs: signEvent(event, [current.privateKey]) }
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
