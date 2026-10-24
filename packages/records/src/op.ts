import {
  findMethodResolver,
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

/** A record op whose signature checked out. `issuer` is the verified signer, normalized. */
export type VerifiedRecordOp = {
  issuer: string
  claim: RecordClaim
  opHash: string
}

/** How many verified record ops {@link verifyRecordOp} keeps, least recently used evicted first. */
export const RECORD_OP_MEMO_SIZE = 1024

type OpMemoEntry = { iss: string; op: VerifiedRecordOp }

// Module-level, so every store, adapter and chunk shares it. Only self-certifying issuers are kept:
// an op token has no time claims, so verifying it is a pure function of its bytes and the op kind.
const opMemo = new Map<string, OpMemoEntry>()

/**
 * Whether `iss` resolves from the token alone: `did:key` carries its key and a `did:peer:4`
 * document is fixed by its hash. A registry entry for the method takes over resolution, and its
 * keys may rotate, so such an issuer is never remembered across calls.
 */
function selfCertifying(iss: string, methods?: MethodRegistry): boolean {
  if (!iss.startsWith('did:key:') && !iss.startsWith('did:peer:4')) return false
  return methods == null || findMethodResolver(methods, iss) === undefined
}

/** A caller may change what it gets back. Never hand out the remembered object itself. */
function copyOp(op: VerifiedRecordOp): VerifiedRecordOp {
  // A claim is decoded from canonical JSON, so a JSON round trip copies it exactly.
  const claim: RecordClaim = JSON.parse(JSON.stringify(op.claim))
  return { issuer: op.issuer, claim, opHash: op.opHash }
}

/** Forget every remembered op. Test-only; not exported from the package. */
export function clearRecordOpMemo(): void {
  opMemo.clear()
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
  opKind: string,
): boolean {
  const { iss, kind, claim } = payload
  if (
    typeof iss !== 'string' ||
    typeof kind !== 'string' ||
    kind !== opKind ||
    typeof claim !== 'string'
  )
    return false
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

// The last signing call queued for each identity. A hardware or prompting signer must never
// see overlapping calls, so each call waits for the one before it, settled either way.
const signingQueues = new WeakMap<SigningIdentity, Promise<unknown>>()

/**
 * Sign a record claim under the caller's required replay domain `opKind`. The token carries the canonical claim bytes rather than the claim
 * as JSON members, so what a verifier reads back is byte-for-byte what was signed.
 *
 * Calls for one identity reach it one at a time, in the order they were made, so callers may
 * sign several records at once.
 *
 * @throws RecordClaimError when the claim is malformed.
 * @throws RecordOpSigningError when the identity produces an unverifiable record-op envelope.
 */
export async function signRecordOp(
  identity: SigningIdentity,
  claim: RecordClaim,
  opKind: string,
): Promise<{ opJWT: string; opHash: string }> {
  const bytes = canonicalRecordClaim(claim)
  const previous = signingQueues.get(identity) ?? Promise.resolve()
  // Queued entries never reject, so a failed call does not stop the next one.
  const signing = previous.then(() => {
    return identity.signToken({ kind: opKind, claim: toB64U(bytes) }, { embedLongForm: true })
  })
  // The queue only orders calls. Each caller sees its own failure.
  signingQueues.set(
    identity,
    signing.catch(() => {}),
  )
  const signed = await signing
  const opJWT = stringifyToken(signed)
  if (
    !isCanonicalCompactToken(opJWT) ||
    !hasRecordOpEnvelope(signed.payload, signed.header, opKind) ||
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
 * Verify a record op under the required `opKind` and extract its claim. Returns `null` (never throws) when the token is
 * unparseable, unsigned (`alg: 'none'`), not a record op, or carries a malformed or
 * non-canonical claim.
 *
 * The issuer is taken only from the verified `iss` — the claim's `owner` is the author's
 * assertion, and whether the issuer may write for that owner is the type's decision.
 */
export async function verifyRecordOp(
  opJWT: string,
  opKind: string,
  methods?: MethodRegistry,
): Promise<VerifiedRecordOp | null> {
  if (!isCanonicalCompactToken(opJWT)) {
    return null
  }
  const opHash = recordOpHash(opJWT)
  // Keyed on the token's digest: the same bytes under the same kind verify the same way.
  const memoKey = JSON.stringify([opKind, opHash])
  const known = opMemo.get(memoKey)
  if (known !== undefined && selfCertifying(known.iss, methods)) {
    // Refreshed, so the least recently used entry is the one evicted.
    opMemo.delete(memoKey)
    opMemo.set(memoKey, known)
    return copyOp(known.op)
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
  if (!hasRecordOpEnvelope(verified.payload, verified.header, opKind)) return null
  const { iss, claim } = verified.payload
  if (typeof iss !== 'string' || typeof claim !== 'string') return null
  const decoded = decodeClaim(claim)
  if (decoded === null) {
    return null
  }
  const op = { issuer: normalizeDID(iss), claim: decoded, opHash }
  // Only successes are kept. A refusal is recomputed on every call.
  if (selfCertifying(iss, methods)) {
    opMemo.set(memoKey, { iss, op: copyOp(op) })
    if (opMemo.size > RECORD_OP_MEMO_SIZE) {
      const oldest = opMemo.keys().next().value
      if (oldest !== undefined) opMemo.delete(oldest)
    }
  }
  return op
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
  opKind: string,
  methods?: MethodRegistry,
): Promise<VerifiedRecordOp | null> {
  return bindRecord(record, await verifyRecordOp(record.opJWT, opKind, methods))
}

function bindRecord(
  record: SignedRecord,
  verified: VerifiedRecordOp | null,
): VerifiedRecordOp | null {
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

/**
 * {@link verifySignedRecord} that verifies each distinct op token once for the verifier's
 * lifetime, whatever its issuer's DID method. Scope one to a single operation, such as one apply
 * chunk: a resolved issuer's keys may rotate between operations.
 */
export function createRecordVerifier(
  opKind: string,
  methods?: MethodRegistry,
): (record: SignedRecord) => Promise<VerifiedRecordOp | null> {
  const ops = new Map<string, Promise<VerifiedRecordOp | null>>()
  return async (record) => {
    let pending = ops.get(record.opJWT)
    if (pending === undefined) {
      pending = verifyRecordOp(record.opJWT, opKind, methods)
      ops.set(record.opJWT, pending)
    }
    const op = await pending
    return bindRecord(record, op === null ? null : copyOp(op))
  }
}
