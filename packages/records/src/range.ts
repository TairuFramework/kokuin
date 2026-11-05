import { nobleCrypto } from '@kokuin/crypto'
import { type CryptoOptions, normalizeDID } from '@kokuin/token'
import { fromB64U, fromUTF, toB64U, toUTF } from '@sozai/codec'

import { parseCanonicalHLC } from './clock.js'
import type { RecordDecision } from './decision.js'
import type { VerifiedRecordOp } from './op.js'
import { type MergePolicy, readVersion } from './policy.js'
import { isRecordClaim, MAX_RECORD_ID_LENGTH, type RecordKey, recordSignerKey } from './record.js'

export type RecordRangeErrorParams = { message: string; options?: ErrorOptions }
export type SplitRangeParams = {
  leaves: ReadonlyArray<RangeLeaf>
  rangeBounds: RangeBounds
  leafThreshold: number
} & CryptoOptions

/**
 * One owner-qualified decision as range reconciliation sees it. `opHash` is the leaf hash
 * of its content digest and sorted held signer set.
 */
export type RangeLeaf = {
  type: string
  owner: string
  id: string
  opHash: string
  order: string
  contentDigest: string
  signers: ReadonlyArray<string>
}

/**
 * The owner-and-id positions of one type from `lower` (exclusive) to `upper` (inclusive);
 * `null` is unbounded. Positions compare as JavaScript strings, by UTF-16 code unit.
 */
export type RangeBounds = { type: string; lower: string | null; upper: string | null }

export type RangeSummary = { bounds: RangeBounds; fingerprint: string; count: number }

/** A range small enough to send as its leaves, in id order. */
export type RangeLeafList = { bounds: RangeBounds; leaves: Array<RangeLeaf> }

/** How many sub-ranges a differing range splits into. */
export const RANGE_SPLIT = 16

/** A differing range with at most this many records is listed rather than split. */
export const RANGE_LEAF_THRESHOLD = 16

/** Thrown when range input could not come from a well-formed store or pass. */
export class RecordRangeError extends Error {
  constructor({ message, options }: RecordRangeErrorParams) {
    super(message, options)
    this.name = 'RecordRangeError'
  }
}

/** 0000-01-01T00:00:00.000Z, the first instant with a four-digit ISO year. */
const MIN_ISO_WALL_TIME = -62_167_219_200_000

/** 9999-12-31T23:59:59.999Z, the last instant with a four-digit ISO year. */
const MAX_ISO_WALL_TIME = 253_402_300_799_999

const OP_HASH_BYTES = 32
const LANES = OP_HASH_BYTES / 4
const FINGERPRINT_BYTES = 16

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

/**
 * Check a leaf that arrived from a responder: an id within `MAX_RECORD_ID_LENGTH` and
 * canonical 32-byte leaf and content digests, with a sorted signer set.
 *
 * @throws RecordRangeError when either is not.
 */
export function assertListedLeaf(leaf: RangeLeaf): void {
  if (leaf.id.length > MAX_RECORD_ID_LENGTH) {
    throw new RecordRangeError({ message: 'Listed id is longer than the id bound' })
  }
  opHashBytes(leaf.opHash)
  opHashBytes(leaf.contentDigest)
  if (
    leaf.signers.some((signer, index) => index > 0 && signer <= (leaf.signers[index - 1] as string))
  ) {
    throw new RecordRangeError({ message: 'Listed signers are not a sorted set' })
  }
}

function opHashBytes(opHash: string): Uint8Array {
  let bytes: Uint8Array
  try {
    bytes = fromB64U(opHash)
  } catch (cause) {
    // biome-ignore lint/style/useErrorCause: the params object forwards options.cause.
    throw new RecordRangeError({ message: 'Op hash is not base64url', options: { cause } })
  }
  // One spelling per hash, or two leaves for the same op could sum differently.
  if (bytes.length !== OP_HASH_BYTES || toB64U(bytes) !== opHash) {
    throw new RecordRangeError({ message: 'Op hash is not a canonical 32-byte digest' })
  }
  return bytes
}

/**
 * `hash(sum || count)` over a set of leaves: `sum` adds every leaf hash as eight big-endian
 * 32-bit words with unsigned wrap, and `count` follows as one big-endian 32-bit word. Addition
 * makes it independent of leaf order and lets a cached sum absorb an insert or a delete; the
 * count keeps sets whose sums happen to agree apart when their sizes differ.
 *
 * Not collision-resistant against a crafted set: a collision can only hide a difference from
 * one pass, never corrupt a store, since fetched records still go through every apply check.
 *
 * @throws RecordRangeError when an `opHash` is not a canonical 32-byte digest.
 */
export type FingerprintRangeParams = { leaves: ReadonlyArray<RangeLeaf> } & CryptoOptions

export async function fingerprintRange({
  leaves,
  ...options
}: FingerprintRangeParams): Promise<string> {
  const sum = new Uint32Array(LANES)
  for (const leaf of leaves) {
    const view = new DataView(opHashBytes(leaf.opHash).buffer)
    for (let lane = 0; lane < LANES; lane++) {
      sum[lane] = ((sum[lane] as number) + view.getUint32(lane * 4, false)) >>> 0
    }
  }
  const input = new Uint8Array(OP_HASH_BYTES + 4)
  const view = new DataView(input.buffer)
  for (let lane = 0; lane < LANES; lane++) {
    view.setUint32(lane * 4, sum[lane] as number, false)
  }
  view.setUint32(OP_HASH_BYTES, leaves.length, false)
  return toB64U(await (options.crypto ?? nobleCrypto).blake3({ input, dkLen: FINGERPRINT_BYTES }))
}

/** Whether a record's key falls inside a range. */
export function rangePosition(key: Pick<RecordKey, 'owner' | 'id'>): string {
  return JSON.stringify([key.owner, key.id])
}

export type RangeContainsParams = { bounds: RangeBounds; key: RecordKey }

export function rangeContains({ key, bounds }: RangeContainsParams): boolean {
  const position = rangePosition(key)
  return (
    key.type === bounds.type &&
    (bounds.lower === null || position > bounds.lower) &&
    (bounds.upper === null || position <= bounds.upper)
  )
}

/**
 * The leaves inside a range, in id order. A store holds one op per record, so two leaves for
 * one key mean the input is not a store's view, and no fingerprint of it would mean anything.
 */
function leavesIn(leaves: ReadonlyArray<RangeLeaf>, bounds: RangeBounds): Array<RangeLeaf> {
  const inside = leaves
    .filter((leaf) => rangeContains({ bounds, key: leaf }))
    .sort((left, right) => compareStrings(rangePosition(left), rangePosition(right)))
  for (let index = 1; index < inside.length; index++) {
    if (
      rangePosition(inside[index] as RangeLeaf) === rangePosition(inside[index - 1] as RangeLeaf)
    ) {
      throw new RecordRangeError({ message: 'Two leaves for one record' })
    }
  }
  return inside
}

/** A responder's summary of one range, scanning its (already visibility-filtered) leaves. */
export type SummarizeRangeParams = {
  leaves: ReadonlyArray<RangeLeaf>
  rangeBounds: RangeBounds
} & CryptoOptions

export async function summarizeRange({
  rangeBounds,
  leaves,
  ...options
}: SummarizeRangeParams): Promise<RangeSummary> {
  const bounds = { ...rangeBounds }
  const inside = leavesIn(leaves, bounds).map((leaf) => ({ ...leaf, signers: [...leaf.signers] }))
  return {
    bounds,
    fingerprint: await fingerprintRange({ ...options, leaves: inside }),
    count: inside.length,
  }
}

/**
 * A responder's answer to a range the requester says differs, scanning its (already
 * visibility-filtered) leaves: the range's leaves when it holds at most `leafThreshold`,
 * otherwise up to `RANGE_SPLIT` summaries of consecutive sub-ranges that partition it. Every
 * sub-range bound is an id the responder holds, and none is listed until the requester says
 * that it differs too.
 *
 * @throws RecordRangeError when `leafThreshold` is not a positive integer, since a range of
 * one record could then split into itself forever.
 */
export async function splitRange({
  leaves,
  rangeBounds,
  leafThreshold,
  crypto,
}: SplitRangeParams): Promise<Array<RangeSummary | RangeLeafList>> {
  const options = { crypto: crypto ?? nobleCrypto }
  if (!Number.isInteger(leafThreshold) || leafThreshold < 1) {
    throw new RecordRangeError({ message: 'Leaf threshold must be a positive integer' })
  }
  const bounds = { ...rangeBounds }
  const inside = leavesIn(leaves, bounds).map((leaf) => ({ ...leaf, signers: [...leaf.signers] }))
  if (inside.length <= leafThreshold) {
    return [{ bounds, leaves: inside }]
  }
  const size = Math.ceil(inside.length / RANGE_SPLIT)
  const children: Array<RangeSummary> = []
  for (let start = 0; start < inside.length; start += size) {
    const chunk = inside.slice(start, start + size)
    const last = start + size >= inside.length
    const childBounds: RangeBounds = {
      type: bounds.type,
      lower: start === 0 ? bounds.lower : rangePosition(inside[start - 1] as RangeLeaf),
      upper: last ? bounds.upper : rangePosition(chunk.at(-1) as RangeLeaf),
    }
    children.push({
      bounds: childBounds,
      fingerprint: await fingerprintRange({ ...options, leaves: chunk }),
      count: chunk.length,
    })
  }
  return children
}

/**
 * A float64 as 16 hex digits whose string order is numeric order: the sign bit is flipped
 * for a positive number and every bit inverted for a negative one. `-0` is written as `0`,
 * which the policy's subtraction treats as equal to it.
 */
function sortableNumber(value: number): string {
  const view = new DataView(new ArrayBuffer(8))
  view.setFloat64(0, value === 0 ? 0 : value, false)
  let high = view.getUint32(0, false)
  let low = view.getUint32(4, false)
  if (high & 0x80000000) {
    high = ~high >>> 0
    low = ~low >>> 0
  } else {
    high = (high | 0x80000000) >>> 0
  }
  return high.toString(16).padStart(8, '0') + low.toString(16).padStart(8, '0')
}

/**
 * A decision's leaf, with `order` the value its type's policy compares decisions by, spelled so that
 * string order is policy order:
 * - `lww`: the canonical stamp;
 * - `monotonic`: the canonical HLC when explicitly declared, otherwise each version part as a
 *   fixed-width sortable number, concatenated, so a tuple extending an equal prefix sorts after it;
 * - `immutable`: the content digest, since the greater one wins.
 *
 * Between different decisions at an equal `order`, the policy prefers the greater content digest.
 *
 * `null` when the policy cannot order the op. A responder then leaves the record out of its
 * ranges, and a requester treats it as a record it lacks, so a fetched op can replace it.
 */
export type RangeLeafParams = { decision: RecordDecision; policy: MergePolicy } & CryptoOptions

export async function rangeLeaf({
  policy,
  decision,
  ...options
}: RangeLeafParams): Promise<RangeLeaf | null> {
  const key = { ...decision.key }
  const contentDigest = decision.contentDigest
  const validCopies = decision.copies.flatMap((copy) => {
    try {
      const parts = copy.opJWT.split('.')
      if (parts.length !== 3) return []
      const token = JSON.parse(toUTF(fromB64U(parts[1] as string))) as {
        iss?: unknown
        claim?: unknown
      }
      if (typeof token.iss !== 'string' || typeof token.claim !== 'string') return []
      const claim: unknown = JSON.parse(toUTF(fromB64U(token.claim)))
      if (
        !isRecordClaim(claim) ||
        claim.type !== decision.key.type ||
        claim.owner !== decision.key.owner ||
        claim.id !== decision.key.id ||
        claim.hlc !== copy.hlc ||
        (policy.kind === 'monotonic' &&
          (readVersion(policy.version, claim) === null ||
            (policy.versionOrder === 'hlc' &&
              (typeof claim.meta.version !== 'string' ||
                parseCanonicalHLC(claim.meta.version) === null))))
      )
        return []
      const signer = recordSignerKey({ issuer: normalizeDID(token.iss), opJWT: copy.opJWT })
      return signer === null ? [] : [{ claim, issuer: signer, opHash: copy.opHash }]
    } catch {
      return []
    }
  })
  const first = validCopies[0]
  if (first === undefined) return null
  const claim = first.claim
  const order =
    policy.kind === 'immutable'
      ? decision.contentDigest
      : policy.kind === 'monotonic' && policy.versionOrder === 'hlc'
        ? (claim.meta.version as string)
        : orderOf(first, policy)
  if (order === null) return null
  if (policy.kind === 'lww') {
    const stamp = parseCanonicalHLC(order)
    if (stamp === null || stamp.wallTime < MIN_ISO_WALL_TIME || stamp.wallTime > MAX_ISO_WALL_TIME)
      return null
  }
  const signers = [...new Set(validCopies.map((copy) => copy.issuer))].sort()
  const opHash = toB64U(
    await (options.crypto ?? nobleCrypto).blake3({
      input: fromUTF(JSON.stringify([contentDigest, signers])),
      dkLen: 32,
    }),
  )
  return { ...key, opHash, order, contentDigest, signers }
}

function orderOf(
  op: Pick<VerifiedRecordOp, 'claim' | 'opHash'>,
  policy: MergePolicy,
): string | null {
  switch (policy.kind) {
    case 'lww': {
      // An ISO date outside years 0000-9999 carries a sign and extra digits, so its string no
      // longer sorts by time.
      const stamp = parseCanonicalHLC(op.claim.hlc)
      return stamp === null ||
        stamp.wallTime < MIN_ISO_WALL_TIME ||
        stamp.wallTime > MAX_ISO_WALL_TIME
        ? null
        : op.claim.hlc
    }
    case 'monotonic': {
      const version = readVersion(policy.version, op.claim)
      return version === null ? null : version.map((part) => sortableNumber(part)).join('')
    }
    case 'immutable':
      return op.opHash
  }
}
