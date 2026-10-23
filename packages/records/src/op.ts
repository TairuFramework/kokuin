import {
  isVerifiedToken,
  type MethodRegistry,
  normalizeDID,
  type SignedPayload,
  type SigningIdentity,
  stringifyToken,
  type VerifiedToken,
  verifyToken,
} from '@kokuin/token'
import { blake3 } from '@noble/hashes/blake3.js'
import { fromB64U, fromUTF, toB64U, toUTF } from '@sozai/codec'

import {
  canonicalRecordClaim,
  isRecordClaim,
  type RecordClaim,
  type SignedRecord,
} from './record.js'

/**
 * Marks a token as a record op, so a signature the same identity made for another purpose
 * cannot be replayed as one.
 */
const RECORD_OP_KIND = 'kubun/record-op'

/** A record op whose signature checked out. `issuer` is the verified signer, normalized. */
export type VerifiedRecordOp = {
  issuer: string
  claim: RecordClaim
  opHash: string
}

/** Thrown when an identity signs an envelope that record-op verification cannot accept. */
export class RecordOpSigningError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RecordOpSigningError'
  }
}

/**
 * Length-prefixed, not delimited, the same framing credential ops hash their tokens with:
 * a separator would only be unambiguous while every part stayed inside an alphabet that
 * excludes it.
 */
function digestParts(parts: Array<string>): string {
  const framed = parts.map((part) => `${part.length}:${part}`).join('')
  return toB64U(blake3(fromUTF(framed), { dkLen: 32 }))
}

/** The address of an op: a digest of its exact token string. */
function recordOpHash(opJWT: string): string {
  return digestParts([opJWT])
}

/**
 * Whether a token is spelled in the one way a signer produces it: three unpadded
 * base64url segments. The token verifier accepts padding, and the signature segment is not
 * part of the signed input, so without this a third party could re-spell an author's op —
 * same claim, same issuer — under a different `opHash`.
 */
function isCanonicalCompactToken(opJWT: string): boolean {
  const segments = opJWT.split('.')
  if (segments.length !== 3) {
    return false
  }
  try {
    return segments.every((segment) => toB64U(fromB64U(segment)) === segment)
  } catch {
    return false
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}

function hasRecordOpEnvelope(
  payload: Record<string, unknown>,
  header: Record<string, unknown>,
): boolean {
  const { iss, kind, claim } = payload
  if (typeof iss !== 'string' || kind !== RECORD_OP_KIND || typeof claim !== 'string') return false
  const payloadKeys = Object.keys(payload).sort()
  if (
    payloadKeys.length !== 3 ||
    payloadKeys[0] !== 'claim' ||
    payloadKeys[1] !== 'iss' ||
    payloadKeys[2] !== 'kind'
  )
    return false
  const headerKeys = Object.keys(header).sort()
  const kid = header.kid
  return !(
    header.alg !== 'EdDSA' ||
    header.typ !== 'JWT' ||
    (kid === undefined
      ? headerKeys.length !== 2 || headerKeys[0] !== 'alg' || headerKeys[1] !== 'typ'
      : typeof kid !== 'string' ||
        headerKeys.length !== 3 ||
        headerKeys[0] !== 'alg' ||
        headerKeys[1] !== 'kid' ||
        headerKeys[2] !== 'typ') ||
    (iss.startsWith('did:key:') && kid !== undefined) ||
    ((iss.startsWith('did:peer:4') || iss.startsWith('did:kokuin:')) && kid === undefined) ||
    (iss.startsWith('did:peer:4') && normalizeDID(iss) === iss)
  )
}

/**
 * Sign a record claim. The token carries the canonical claim bytes rather than the claim
 * as JSON members, so what a verifier reads back is byte-for-byte what was signed.
 *
 * @throws RecordClaimError when the claim is malformed.
 * @throws RecordOpSigningError when the identity produces an unverifiable record-op envelope.
 */
export async function signRecordOp(
  identity: SigningIdentity,
  claim: RecordClaim,
): Promise<{ opJWT: string; opHash: string }> {
  const bytes = canonicalRecordClaim(claim)
  const signed = await identity.signToken(
    { kind: RECORD_OP_KIND, claim: toB64U(bytes) },
    { embedLongForm: true },
  )
  const opJWT = stringifyToken(signed)
  if (
    !isCanonicalCompactToken(opJWT) ||
    !hasRecordOpEnvelope(signed.payload, signed.header) ||
    typeof signed.payload.iss !== 'string' ||
    normalizeDID(signed.payload.iss) !== normalizeDID(identity.id) ||
    signed.payload.claim !== toB64U(bytes)
  ) {
    throw new RecordOpSigningError('Identity produced a record op envelope that cannot be verified')
  }
  return { opJWT, opHash: recordOpHash(opJWT) }
}

function decodeClaim(encoded: string): RecordClaim | null {
  let bytes: Uint8Array
  let parsed: unknown
  try {
    bytes = fromB64U(encoded)
    parsed = JSON.parse(toUTF(bytes))
  } catch {
    return null
  }
  if (!isRecordClaim(parsed)) {
    return null
  }
  // One spelling per claim: bytes that parse to a valid claim but are not its canonical
  // encoding are refused, so two tokens can never sign the same claim in different bytes.
  return bytesEqual(canonicalRecordClaim(parsed), bytes) ? parsed : null
}

/**
 * Verify a record op and extract its claim. Returns `null` (never throws) when the token is
 * unparseable, unsigned (`alg: 'none'`), not a record op, or carries a malformed or
 * non-canonical claim.
 *
 * The issuer is taken only from the verified `iss` — the claim's `owner` is the author's
 * assertion, and whether the issuer may write for that owner is the type's decision.
 */
export async function verifyRecordOp(
  opJWT: string,
  methods?: MethodRegistry,
): Promise<VerifiedRecordOp | null> {
  if (!isCanonicalCompactToken(opJWT)) {
    return null
  }
  let verified: VerifiedToken<Record<string, unknown>>
  try {
    verified = await verifyToken<Record<string, unknown>>(opJWT, { methods })
  } catch {
    return null
  }
  if (!isVerifiedToken<SignedPayload & Record<string, unknown>>(verified)) {
    return null
  }
  if (!hasRecordOpEnvelope(verified.payload, verified.header)) return null
  const { iss, claim } = verified.payload
  if (typeof iss !== 'string' || typeof claim !== 'string') return null
  const decoded = decodeClaim(claim)
  if (decoded === null) {
    return null
  }
  return { issuer: normalizeDID(iss), claim: decoded, opHash: recordOpHash(opJWT) }
}

/**
 * Verify a stored or received record's op and check that the record's indexed fields and
 * `opHash` are the ones it signed. Returns `null` on any mismatch — a record whose `owner`
 * differs from its claim is a takeover attempt, not a record.
 *
 * The payload is not checked here: `recordPayloadMatches` does that, so a caller can order
 * it after the merge decision.
 */
export async function verifySignedRecord(
  record: SignedRecord,
  methods?: MethodRegistry,
): Promise<VerifiedRecordOp | null> {
  const verified = await verifyRecordOp(record.opJWT, methods)
  if (verified === null) {
    return null
  }
  const { claim, opHash } = verified
  if (
    claim.type !== record.type ||
    claim.id !== record.id ||
    claim.owner !== record.owner ||
    claim.hlc !== record.hlc ||
    opHash !== record.opHash
  ) {
    return null
  }
  return verified
}
