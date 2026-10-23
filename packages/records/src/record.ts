import { normalizeDID } from '@kokuin/token'
import { blake3 } from '@noble/hashes/blake3.js'
import { canonicalStringify, fromB64U, fromUTF, toB64U, toUTF } from '@sozai/codec'
import { isJSONValue } from '@sozai/json'

/**
 * What the author of a record signs.
 *
 * A digest rather than the payload: an op travels beside the bytes it speaks for, so
 * repeating them in the signature would double every record on the wire. `payloadDigest`
 * is `null` exactly when `deleted` — a tombstone has no payload, and a digest of nothing
 * would be a constant every tombstone shared.
 *
 * `meta` holds the fields a merge policy reads. It must have a lossless JSON form, since
 * the claim is signed as canonical JSON bytes and read back from them.
 */
export type RecordClaim = {
  type: string
  id: string
  owner: string
  hlc: string
  payloadDigest: string | null
  deleted: boolean
  meta: Record<string, unknown>
}

/**
 * A record as it is stored and sent: the opaque payload beside the op that signs for it.
 *
 * `type`, `id`, `owner` and `hlc` repeat claim fields so a store can index them without
 * verifying a token; `verifySignedRecord` is what makes that repetition trustworthy.
 */
export type SignedRecord = {
  type: string
  id: string
  owner: string
  hlc: string
  payload: Uint8Array | null
  opJWT: string
  opHash: string
}

export type RecordKey = { type: string; owner: string; id: string }

/** A verified copy's issuer and the key selected by its signed token header. */
export function recordSignerKey(issuer: string, opJWT: string): string | null {
  try {
    const header = JSON.parse(toUTF(fromB64U(opJWT.split('.')[0] as string))) as {
      kid?: unknown
    }
    return header.kid === undefined
      ? issuer
      : typeof header.kid === 'string'
        ? `${issuer}${header.kid}`
        : null
  } catch {
    return null
  }
}

export function recordClaimDigest(claim: RecordClaim): string {
  const decisionHLC = typeof claim.meta.version === 'string' ? claim.meta.version : claim.hlc
  return toB64U(blake3(canonicalRecordClaim({ ...claim, hlc: decisionHLC }), { dkLen: 32 }))
}

/** Thrown when a claim cannot be signed as given. */
export class RecordClaimError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RecordClaimError'
  }
}

/**
 * The longest record id, in UTF-16 code units. A range lists ids to requesters, which refuse
 * a longer one, so a record past it could be stored but never replicated; the claim check
 * refuses it instead, and apply with it.
 */
export const MAX_RECORD_ID_LENGTH = 1024

const CLAIM_KEYS = ['deleted', 'hlc', 'id', 'meta', 'owner', 'payloadDigest', 'type']

/**
 * An owner is compared by its string wherever a record is bound to it, so it must have one
 * spelling: a peer:4 DID in its long form names the same owner as its short form, and would
 * otherwise fail an owner comparison against it.
 */
function isNormalizedDID(value: string): boolean {
  try {
    return normalizeDID(value) === value
  } catch {
    return false
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

// Only values that survive a JSON round trip unchanged: an `undefined` member or a `NaN` would
// be dropped or rewritten by serialization, so the verified claim would differ from the one the
// author passed in. `isJSONValue` accepts `-0`, which `canonicalStringify` rewrites to `0`: two
// distinct signed ops would then share one claim digest, so it is rejected here. Only called on
// a value `isJSONValue` already accepted, so no cycle guard.
function containsNegativeZero(value: unknown): boolean {
  if (typeof value === 'number') {
    return Object.is(value, -0)
  }
  if (Array.isArray(value)) {
    return value.some(containsNegativeZero)
  }
  if (isPlainObject(value)) {
    return Object.values(value).some(containsNegativeZero)
  }
  return false
}

/**
 * Whether a value has exactly the claim shape. Extra fields fail, since a verifier that
 * ignored them would accept bytes the author never meant as part of the claim.
 */
export function isRecordClaim(value: unknown): value is RecordClaim {
  if (!isPlainObject(value)) {
    return false
  }
  const keys = Object.keys(value).sort()
  if (keys.length !== CLAIM_KEYS.length || keys.some((key, index) => key !== CLAIM_KEYS[index])) {
    return false
  }
  const { type, id, owner, hlc, payloadDigest, deleted, meta } = value
  return (
    typeof type === 'string' &&
    typeof id === 'string' &&
    id.length <= MAX_RECORD_ID_LENGTH &&
    typeof owner === 'string' &&
    isNormalizedDID(owner) &&
    typeof hlc === 'string' &&
    typeof deleted === 'boolean' &&
    // A live op with no digest would authenticate any bytes at all, so the two fields are
    // checked against each other rather than one at a time.
    (deleted ? payloadDigest === null : typeof payloadDigest === 'string') &&
    isPlainObject(meta) &&
    isJSONValue(meta) &&
    !containsNegativeZero(meta)
  )
}

/**
 * The bytes a record op signs: the claim as canonical JSON (object keys sorted
 * recursively, array order kept), UTF-8 encoded.
 *
 * @throws RecordClaimError when the claim is malformed.
 */
export function canonicalRecordClaim(claim: RecordClaim): Uint8Array {
  if (!isRecordClaim(claim)) {
    throw new RecordClaimError('Record claim is malformed')
  }
  return fromUTF(canonicalStringify(claim))
}

/**
 * Digest of the exact payload bytes — never of a parsed form, since the primitive does not
 * know whether the payload is ciphertext or JSON. `null` for a tombstone's absent payload.
 */
export function recordPayloadDigest(payload: Uint8Array | null): string | null {
  return payload === null ? null : toB64U(blake3(payload, { dkLen: 32 }))
}

/** Whether a record's payload is the one its claim signed for. */
export function recordPayloadMatches(record: SignedRecord, claim: RecordClaim): boolean {
  return recordPayloadDigest(record.payload) === claim.payloadDigest
}
