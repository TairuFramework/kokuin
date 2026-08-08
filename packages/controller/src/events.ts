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
