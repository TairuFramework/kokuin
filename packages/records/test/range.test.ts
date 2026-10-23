import { blake3 } from '@noble/hashes/blake3.js'
import { fromUTF, toB64U } from '@sozai/codec'
import { HLC } from '@sozai/hlc'
import { describe, expect, test } from 'vitest'

import {
  compareRecordOps,
  fingerprintRange,
  type MergePolicy,
  RANGE_LEAF_THRESHOLD,
  RANGE_SPLIT,
  type RangeBounds,
  type RangeLeaf,
  type RangeLeafList,
  type RangeSummary,
  type RecordClaim,
  type RecordDecision,
  RecordRangeError,
  rangeContains,
  rangeLeaf,
  rangePosition,
  type SignedRecord,
  splitRange,
  summarizeRange,
  type VerifiedRecordOp,
} from '../src/index.js'

const TYPE = 'credential.entry'
const OWNER = 'owner'
const position = (id: string) => rangePosition({ owner: OWNER, id })
const WHOLE: RangeBounds = { type: TYPE, lower: null, upper: null }

function hashOf(seed: string): string {
  return toB64U(blake3(fromUTF(seed), { dkLen: 32 }))
}

function leafAt(index: number, type = TYPE): RangeLeaf {
  return {
    type,
    owner: OWNER,
    id: `id-${hashOf(`id-${index}`).slice(0, 12)}`,
    opHash: hashOf(`op-${index}`),
    contentDigest: hashOf(`op-${index}`),
    signers: [],
    order: HLC.serialize({ wallTime: 1_790_000_000_000 + index, counter: 0, nodeID: 'node' }),
  }
}

function leaves(count: number, type = TYPE): Array<RangeLeaf> {
  return Array.from({ length: count }, (_, index) => leafAt(index, type))
}

function shuffled<T>(values: ReadonlyArray<T>): Array<T> {
  // Deterministic: reversing and interleaving is enough to break any input order.
  const reversed = [...values].reverse()
  return [
    ...reversed.filter((_, index) => index % 2 === 0),
    ...reversed.filter((_, index) => index % 2 === 1),
  ]
}

/** A 32-byte op hash with every lane set to `lane`, as a big-endian word. */
function laneHash(lane: number): string {
  const bytes = new Uint8Array(32)
  const view = new DataView(bytes.buffer)
  for (let index = 0; index < 8; index++) {
    view.setUint32(index * 4, lane, false)
  }
  return toB64U(bytes)
}

function leafWithHash(id: string, opHash: string): RangeLeaf {
  return { type: TYPE, owner: OWNER, id, opHash, contentDigest: opHash, signers: [], order: '1' }
}

/** The fingerprint byte layout, computed independently: 8 big-endian lanes, then a count. */
function referenceFingerprint(rows: ReadonlyArray<RangeLeaf>): string {
  const sums = Array.from({ length: 8 }, () => 0n)
  for (const row of rows) {
    const bytes = Buffer.from(row.opHash, 'base64url')
    for (let lane = 0; lane < 8; lane++) {
      sums[lane] = ((sums[lane] as bigint) + BigInt(bytes.readUInt32BE(lane * 4))) % 2n ** 32n
    }
  }
  const input = Buffer.alloc(36)
  sums.forEach((sum, lane) => {
    input.writeUInt32BE(Number(sum), lane * 4)
  })
  input.writeUInt32BE(rows.length, 32)
  return toB64U(blake3(new Uint8Array(input), { dkLen: 16 }))
}

function isSummary(child: RangeSummary | RangeLeafList): child is RangeSummary {
  return 'fingerprint' in child
}

describe('fingerprintRange', () => {
  test('does not depend on the order of the leaves', () => {
    const rows = leaves(100)
    expect(fingerprintRange(shuffled(rows))).toBe(fingerprintRange(rows))
  })

  test.each([10, 100, 1000])('is the hash of the lane sum and count at %i rows', (count) => {
    const rows = leaves(count)
    expect(fingerprintRange(rows)).toBe(referenceFingerprint(rows))
  })

  test('adding then removing a leaf restores the fingerprint', () => {
    const rows = leaves(100)
    const extra = leafAt(1000)
    const added = fingerprintRange([...rows, extra])
    expect(added).not.toBe(fingerprintRange(rows))
    expect(added).toBe(referenceFingerprint([...rows, extra]))
    expect(fingerprintRange([...rows, extra].filter((row) => row !== extra))).toBe(
      fingerprintRange(rows),
    )
  })

  test('adds lanes as big-endian words with unsigned wrap', () => {
    // 0x000000ff + 0x00000001 carries into the second byte only when read big-endian;
    // 0xffffffff + 0x00000001 wraps to zero.
    const carry = fingerprintRange([
      leafWithHash('a', laneHash(0xff)),
      leafWithHash('b', laneHash(0x01)),
    ])
    const expectedCarry = new Uint8Array(36)
    const carryView = new DataView(expectedCarry.buffer)
    for (let lane = 0; lane < 8; lane++) {
      carryView.setUint32(lane * 4, 0x100, false)
    }
    carryView.setUint32(32, 2, false)
    expect(carry).toBe(toB64U(blake3(expectedCarry, { dkLen: 16 })))

    const wrapped = fingerprintRange([
      leafWithHash('a', laneHash(0xffffffff)),
      leafWithHash('b', laneHash(0x01)),
    ])
    const expectedWrap = new Uint8Array(36)
    new DataView(expectedWrap.buffer).setUint32(32, 2, false)
    expect(wrapped).toBe(toB64U(blake3(expectedWrap, { dkLen: 16 })))
  })

  test('the count takes part, so equal sums of different sizes differ', () => {
    const zero = laneHash(0)
    const none = fingerprintRange([])
    const one = fingerprintRange([leafWithHash('a', zero)])
    const two = fingerprintRange([leafWithHash('a', zero), leafWithHash('b', zero)])
    const wrapPair = fingerprintRange([
      leafWithHash('a', laneHash(0xffffffff)),
      leafWithHash('b', laneHash(0x01)),
    ])
    expect(new Set([none, one, two]).size).toBe(3)
    // Same zero sum and the same count: the fingerprint cannot tell them apart.
    expect(wrapPair).toBe(two)
  })

  test('refuses an op hash that is not 32 bytes of base64url', () => {
    expect(() => fingerprintRange([leafWithHash('a', 'a')])).toThrow(RecordRangeError)
    expect(() => fingerprintRange([leafWithHash('a', toB64U(new Uint8Array(31)))])).toThrow(
      RecordRangeError,
    )
    expect(() => fingerprintRange([leafWithHash('a', `${laneHash(0)}=`)])).toThrow(RecordRangeError)
  })
})

describe('rangeContains', () => {
  test('bounds are exclusive below, inclusive above, and scoped to one type', () => {
    const bounds: RangeBounds = { type: TYPE, lower: position('b'), upper: position('d') }
    expect(rangeContains(bounds, { type: TYPE, owner: OWNER, id: 'b' })).toBe(false)
    expect(rangeContains(bounds, { type: TYPE, owner: OWNER, id: 'c' })).toBe(true)
    expect(rangeContains(bounds, { type: TYPE, owner: OWNER, id: 'd' })).toBe(true)
    expect(rangeContains(bounds, { type: TYPE, owner: OWNER, id: 'e' })).toBe(false)
    expect(rangeContains(bounds, { type: 'credential.key', owner: OWNER, id: 'c' })).toBe(false)
    expect(rangeContains(WHOLE, { type: TYPE, owner: OWNER, id: '' })).toBe(true)
  })
})

describe('summarizeRange', () => {
  test('covers only the leaves of the range', () => {
    const rows = leaves(40)
    const sorted = [...rows].sort((left, right) => (left.id < right.id ? -1 : 1))
    const bounds: RangeBounds = {
      type: TYPE,
      lower: rangePosition(sorted[9] as RangeLeaf),
      upper: rangePosition(sorted[19] as RangeLeaf),
    }
    const inside = sorted.slice(10, 20)
    const summary = summarizeRange([...rows, ...leaves(5, 'credential.key')], bounds)
    expect(summary).toEqual({ bounds, fingerprint: fingerprintRange(inside), count: 10 })
  })
})

describe('splitRange', () => {
  test('uses the measured configuration', () => {
    expect(RANGE_SPLIT).toBe(16)
    expect(RANGE_LEAF_THRESHOLD).toBe(16)
  })

  test('lists a range at the threshold in id order, without other types or ids', () => {
    const rows = leaves(RANGE_LEAF_THRESHOLD)
    const others = leaves(3, 'credential.key')
    const children = splitRange(shuffled([...rows, ...others]), WHOLE, RANGE_LEAF_THRESHOLD)
    const sorted = [...rows].sort((left, right) => (left.id < right.id ? -1 : 1))
    expect(children).toEqual([{ bounds: WHOLE, leaves: sorted }])
    const [listed] = children as [RangeLeafList]
    expect(listed.leaves.map(({ id, opHash, order }) => ({ id, opHash, order }))).toEqual(
      sorted.map(({ id, opHash, order }) => ({ id, opHash, order })),
    )
  })

  test('lists an empty range as no leaves', () => {
    expect(splitRange([], WHOLE, RANGE_LEAF_THRESHOLD)).toEqual([{ bounds: WHOLE, leaves: [] }])
  })

  test.each([
    [17, 9],
    [100, 15],
    [1000, 16],
  ])('splits %i rows into %i summaries that partition the range', (count, expected) => {
    const rows = leaves(count)
    const children = splitRange(shuffled(rows), WHOLE, RANGE_LEAF_THRESHOLD)
    expect(children).toHaveLength(expected)
    expect(children.every(isSummary)).toBe(true)
    const summaries = children as Array<RangeSummary>

    expect(summaries[0]?.bounds.lower).toBeNull()
    expect(summaries.at(-1)?.bounds.upper).toBeNull()
    summaries.forEach((summary, index) => {
      expect(summary.bounds.type).toBe(TYPE)
      if (index > 0) {
        expect(summary.bounds.lower).toBe(summaries[index - 1]?.bounds.upper)
      }
      const inside = rows.filter((row) => rangeContains(summary.bounds, row))
      expect(summary.count).toBe(inside.length)
      expect(summary.count).toBeGreaterThan(0)
      expect(summary.fingerprint).toBe(fingerprintRange(inside))
    })
    expect(summaries.reduce((total, summary) => total + summary.count, 0)).toBe(count)
  })

  test('splits a bounded sub-range inside its own bounds', () => {
    const rows = leaves(200)
    const sorted = [...rows].sort((left, right) => (left.id < right.id ? -1 : 1))
    const bounds: RangeBounds = {
      type: TYPE,
      lower: rangePosition(sorted[49] as RangeLeaf),
      upper: rangePosition(sorted[149] as RangeLeaf),
    }
    const summaries = splitRange(rows, bounds, RANGE_LEAF_THRESHOLD) as Array<RangeSummary>
    expect(summaries[0]?.bounds.lower).toBe(bounds.lower)
    expect(summaries.at(-1)?.bounds.upper).toBe(bounds.upper)
    expect(summaries.reduce((total, summary) => total + summary.count, 0)).toBe(100)
  })

  test('refuses a threshold that could not make progress', () => {
    expect(() => splitRange(leaves(2), WHOLE, 0)).toThrow(RecordRangeError)
    expect(() => splitRange(leaves(2), WHOLE, 1.5)).toThrow(RecordRangeError)
  })

  test('refuses two leaves for one record', () => {
    const [first] = leaves(1) as [RangeLeaf]
    expect(() =>
      splitRange([first, { ...first, opHash: hashOf('other') }], WHOLE, RANGE_LEAF_THRESHOLD),
    ).toThrow(RecordRangeError)
  })
})

const T0 = Date.parse('2026-09-26T00:00:00.000Z')

function op(opHash: string, claim: Partial<RecordClaim> = {}): VerifiedRecordOp {
  return {
    issuer: 'did:key:owner',
    opHash,
    claim: {
      type: TYPE,
      id: 'record-1',
      owner: 'did:key:owner',
      hlc: HLC.serialize({ wallTime: T0, counter: 0, nodeID: 'node' }),
      payloadDigest: 'digest',
      deleted: false,
      meta: {},
      ...claim,
    },
  }
}

const VERSIONED: MergePolicy = {
  kind: 'monotonic',
  version: (claim) => claim.meta.version as ReadonlyArray<number>,
}

function decisionFromOp(op: VerifiedRecordOp): RecordDecision {
  const claim = toB64U(fromUTF(JSON.stringify(op.claim)))
  const payload = toB64U(fromUTF(JSON.stringify({ iss: OWNER, claim })))
  const record = {
    type: op.claim.type,
    owner: op.claim.owner,
    id: op.claim.id,
    hlc: op.claim.hlc,
    payload: null,
    opJWT: `${toB64U(fromUTF(JSON.stringify({ typ: 'JWT', alg: 'EdDSA' })))}.${payload}.signature`,
    opHash: op.opHash,
  }
  return {
    key: { type: record.type, owner: record.owner, id: record.id },
    decisionHLC: op.claim.hlc,
    contentDigest: op.opHash,
    copies: [record],
  }
}

function leafFromOp(op: VerifiedRecordOp, policy: MergePolicy): RangeLeaf | null {
  return rangeLeaf(decisionFromOp(op), policy)
}

describe('rangeLeaf', () => {
  test.each(['first', 'later'])('ignores a malformed %s copy beside a valid copy', (position) => {
    const digest = toB64U(new Uint8Array(32).fill(7))
    const decision = decisionFromOp(op(digest))
    const valid = decision.copies[0] as SignedRecord
    const malformed = {
      ...valid,
      opJWT:
        position === 'first'
          ? 'not-a-token'
          : `header.${toB64U(fromUTF(JSON.stringify({ iss: 'other', claim: 'invalid' })))}.signature`,
    }
    const copies = position === 'first' ? [malformed, valid] : [valid, malformed]
    expect(rangeLeaf({ ...decision, copies }, { kind: 'lww' })).toEqual({
      type: TYPE,
      owner: 'did:key:owner',
      id: 'record-1',
      opHash: hashOf(JSON.stringify([digest, ['owner']])),
      order: HLC.serialize({ wallTime: T0, counter: 0, nodeID: 'node' }),
      contentDigest: digest,
      signers: ['owner'],
    })
  })
  test('keeps non-credential leaf fingerprints at the pre-reissue vector and emits plain leaves', () => {
    const opHash = toB64U(new Uint8Array(32).fill(7))
    const nonCredential = leafFromOp(
      op(opHash, { type: 'catalog.record', meta: { version: [1] } }),
      VERSIONED,
    )
    expect(nonCredential).toEqual({
      type: 'catalog.record',
      owner: 'did:key:owner',
      id: 'record-1',
      opHash: hashOf(JSON.stringify([opHash, ['owner']])),
      order: 'bff0000000000000',
      contentDigest: opHash,
      signers: ['owner'],
    })
    expect(fingerprintRange([nonCredential as RangeLeaf])).toBe('ypCiDdJwWeikqoNKP1qSpw')
    expect(leafFromOp(op(opHash, { meta: { version: [1] } }), VERSIONED)).toEqual({
      type: TYPE,
      owner: 'did:key:owner',
      id: 'record-1',
      opHash: hashOf(JSON.stringify([opHash, ['owner']])),
      order: 'bff0000000000000',
      contentDigest: opHash,
      signers: ['owner'],
    })
  })

  test('orders lww by the canonical stamp', () => {
    const hlc = HLC.serialize({ wallTime: T0 + 5, counter: 3, nodeID: 'node' })
    expect(leafFromOp(op('h', { hlc }), { kind: 'lww' })).toEqual({
      type: TYPE,
      owner: 'did:key:owner',
      id: 'record-1',
      opHash: hashOf(JSON.stringify(['h', ['owner']])),
      contentDigest: 'h',
      order: hlc,
      signers: ['owner'],
    })
  })

  test('leaves out an lww op whose stamp is not canonical', () => {
    expect(leafFromOp(op('h', { hlc: '2026-09-26T00:00:00Z:0:node' }), { kind: 'lww' })).toBeNull()
  })

  test('leaves out an lww op stamped outside the years string order can compare', () => {
    const stamp = (wallTime: number) => HLC.serialize({ wallTime, counter: 0, nodeID: 'node' })
    const yearZero = -62_167_219_200_000
    expect(stamp(yearZero)).toBe('0000-01-01T00:00:00.000Z:00000000:node')
    const before = stamp(yearZero - 1)
    const after = stamp(253_402_300_800_000)
    const first = stamp(yearZero)
    const last = stamp(253_402_300_799_999)
    const preEpoch = stamp(Date.parse('1969-07-20T20:17:00.000Z'))
    expect(leafFromOp(op('h', { hlc: before }), { kind: 'lww' })).toBeNull()
    expect(leafFromOp(op('h', { hlc: after }), { kind: 'lww' })).toBeNull()
    expect(leafFromOp(op('h', { hlc: first }), { kind: 'lww' })?.order).toBe(first)
    expect(leafFromOp(op('h', { hlc: last }), { kind: 'lww' })?.order).toBe(last)
    expect(leafFromOp(op('h', { hlc: preEpoch }), { kind: 'lww' })?.order).toBe(preEpoch)
    // Canonical stamps inside those years sort as strings in time order, before 1970 too.
    const inOrder = [first, preEpoch, stamp(0), last]
    expect([...inOrder].reverse().sort()).toEqual(inOrder)
  })

  test('orders immutable by the op hash', () => {
    expect(leafFromOp(op('h'), { kind: 'immutable' })?.order).toBe('h')
  })

  test('encodes a monotonic version so string order is tuple order', () => {
    const versions: Array<Array<number>> = [
      [],
      [0],
      [1],
      [2],
      [10],
      [-1],
      [-2.5],
      [0.5],
      [1, 0],
      [1, -1],
      [1, 2],
      [2, 0, 0],
      [Number.MAX_VALUE],
      [-Number.MAX_VALUE],
      [Number.MIN_VALUE],
      [-Number.MIN_VALUE],
    ]
    const orderOf = (version: Array<number>) =>
      leafFromOp(op('h', { meta: { version } }), VERSIONED)?.order as string
    for (const left of versions) {
      for (const right of versions) {
        const decision = compareRecordOps(
          op('a', { meta: { version: left } }),
          op('b', { meta: { version: right } }),
          VERSIONED,
        )
        const byOrder = orderOf(left) < orderOf(right) ? -1 : orderOf(left) > orderOf(right) ? 1 : 0
        // The policy applies a greater version, keeps a lesser one and reports an equal one.
        const byPolicy = orderOf(left) === orderOf(right) ? 0 : decision.status === 'apply' ? 1 : -1
        expect([left, right, byOrder]).toEqual([left, right, byPolicy])
      }
    }
  })

  test('leaves out a monotonic op whose version cannot be read', () => {
    expect(leafFromOp(op('h', { meta: { version: [Number.NaN] } }), VERSIONED)).toBeNull()
    expect(leafFromOp(op('h', { meta: {} }), VERSIONED)).toBeNull()
  })
})
