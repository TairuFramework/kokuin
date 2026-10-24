import { blake3 } from '@noble/hashes/blake3.js'
import { toB64U } from '@sozai/codec'
import { HLC } from '@sozai/hlc'
import { describe, expect, test } from 'vitest'

import {
  canonicalRecordClaim,
  compareRecordOps,
  type EqualVersionDecision,
  type MergeDecision,
  type MergePolicy,
  type RecordClaim,
  type VerifiedRecordOp,
} from '../src/index.js'

const T0 = Date.parse('2026-09-26T00:00:00.000Z')

function hlcAt(offsetMS: number, counter = 0, nodeID = 'node'): string {
  return HLC.serialize({ wallTime: T0 + offsetMS, counter, nodeID })
}

function op(opHash: string, claim: Partial<RecordClaim> = {}): VerifiedRecordOp {
  const deleted = claim.deleted ?? false
  return {
    issuer: 'did:key:owner',
    opHash,
    claim: {
      type: 'test.record',
      id: 'record-1',
      owner: 'did:key:owner',
      hlc: hlcAt(0),
      payloadDigest: deleted ? null : opHash,
      deleted,
      meta: {},
      ...claim,
    },
  }
}

function higherContent(left: VerifiedRecordOp, right: VerifiedRecordOp): boolean {
  const digest = (op: VerifiedRecordOp) =>
    toB64U(blake3(canonicalRecordClaim(op.claim), { dkLen: 32 }))
  return digest(left) > digest(right)
}

const LWW: MergePolicy = { kind: 'lww' }
const IMMUTABLE: MergePolicy = { kind: 'immutable' }
const VERSIONED: MergePolicy = {
  kind: 'monotonic',
  version: (claim) => claim.meta.version as ReadonlyArray<number>,
}
const FORK_ON_EQUAL = (): EqualVersionDecision => 'fork'

function versioned(opHash: string, version: Array<number>, rest: Partial<RecordClaim> = {}) {
  return op(opHash, { ...rest, meta: { version } })
}

describe('lww', () => {
  test('the greater hlc wins', () => {
    const older = op('z', { hlc: hlcAt(0) })
    const newer = op('a', { hlc: hlcAt(1) })
    expect(compareRecordOps(newer, older, LWW)).toEqual({ status: 'apply' })
    expect(compareRecordOps(older, newer, LWW)).toEqual({ status: 'noop' })
  })

  test('the counter orders stamps at one wall time, numerically', () => {
    const low = op('z', { hlc: hlcAt(0, 9) })
    const high = op('a', { hlc: hlcAt(0, 10) })
    expect(compareRecordOps(high, low, LWW).status).toBe('apply')
    expect(compareRecordOps(low, high, LWW).status).toBe('noop')
  })

  test('stamps order by time, not by their spelling', () => {
    // Past year 9999 the ISO form gains a sign and two digits, so string order inverts.
    const y9999 = op('z', {
      hlc: HLC.serialize({
        wallTime: Date.parse('9999-12-31T00:00:00.000Z'),
        counter: 0,
        nodeID: 'node',
      }),
    })
    const y10000 = op('a', {
      hlc: HLC.serialize({
        wallTime: Date.parse('+010000-01-01T00:00:00.000Z'),
        counter: 0,
        nodeID: 'node',
      }),
    })
    expect(y10000.claim.hlc < y9999.claim.hlc).toBe(true)
    expect(compareRecordOps(y10000, y9999, LWW).status).toBe('apply')
    expect(compareRecordOps(y9999, y10000, LWW).status).toBe('noop')
  })

  test('an equal hlc goes to the greater content digest', () => {
    const low = op('a', { hlc: hlcAt(0) })
    const high = op('b', { hlc: hlcAt(0) })
    expect(compareRecordOps(high, low, LWW)).toEqual({
      status: higherContent(high, low) ? 'apply' : 'noop',
    })
    expect(compareRecordOps(low, high, LWW)).toEqual({
      status: higherContent(low, high) ? 'apply' : 'noop',
    })
  })

  test('a delete follows the same ordering as a write', () => {
    const write = op('z', { hlc: hlcAt(0) })
    const laterDelete = op('a', { hlc: hlcAt(1), deleted: true })
    const earlierDelete = op('a', { hlc: hlcAt(-1), deleted: true })
    expect(compareRecordOps(laterDelete, write, LWW).status).toBe('apply')
    expect(compareRecordOps(earlierDelete, write, LWW).status).toBe('noop')
    expect(compareRecordOps(write, laterDelete, LWW).status).toBe('noop')
    expect(compareRecordOps(write, earlierDelete, LWW).status).toBe('apply')
  })

  test('the same op is a no-op', () => {
    const stored = op('a')
    expect(compareRecordOps(stored, stored, LWW)).toEqual({ status: 'noop' })
  })

  test('an incoming op with a non-canonical hlc cannot win, however late it looks', () => {
    const stored = op('a', { hlc: hlcAt(0) })
    // One second later with an unpadded counter: parses to finite fields that would win.
    const loose = new Date(T0 + 1000).toISOString()
    const incoming = op('z', { hlc: `${loose}:1:node` })
    expect(HLC.tryParse(incoming.claim.hlc)).not.toBeNull()
    expect(compareRecordOps(incoming, stored, LWW)).toEqual({
      status: 'reject',
      reason: 'hlc-not-canonical',
    })
  })

  test('a stored op with a non-canonical hlc yields to any canonical one', () => {
    const stored = op('z', { hlc: `${new Date(T0 + 1000).toISOString()}:1:node` })
    const incoming = op('a', { hlc: hlcAt(0) })
    expect(compareRecordOps(incoming, stored, LWW)).toEqual({
      status: 'apply',
      reason: 'stored-hlc-not-canonical',
    })
  })
})

describe('monotonic', () => {
  test('a numeric version hook orders string metadata numerically', () => {
    const policy: MergePolicy = {
      kind: 'monotonic',
      version: (claim) => [Number(claim.meta.version)],
    }
    const high = op('a', { meta: { version: '10' } })
    const low = op('z', { meta: { version: '2' } })
    expect(compareRecordOps(high, low, policy).status).toBe('apply')
    expect(compareRecordOps(low, high, policy).status).toBe('noop')
  })

  test('an HLC version policy rejects non-canonical string metadata on first write', () => {
    const policy: MergePolicy = {
      kind: 'monotonic',
      versionOrder: 'hlc',
      version: (claim) => [HLC.tryParse(String(claim.meta.version))?.counter ?? Number.NaN],
    }
    const loose = op('a', { meta: { version: '2026-09-26T00:00:00.000Z:1:z' } })
    expect(compareRecordOps(loose, null, policy)).toEqual({
      status: 'reject',
      reason: 'version-invalid',
    })
  })

  test('an HLC version policy orders canonical counters ahead of content digests', () => {
    const policy: MergePolicy = {
      kind: 'monotonic',
      versionOrder: 'hlc',
      version: () => [0],
    }
    const high = op('high', { meta: { version: hlcAt(0, 10, 'a') } })
    let low: VerifiedRecordOp | null = null
    for (let index = 0; index < 32; index++) {
      const candidate = op(`low-${index}`, { meta: { version: hlcAt(0, 2, 'z') } })
      if (higherContent(candidate, high)) {
        low = candidate
        break
      }
    }
    if (low === null) throw new Error('no opposing digest fixture')
    expect(compareRecordOps(high, low, policy).status).toBe('apply')
    expect(compareRecordOps(low, high, policy).status).toBe('noop')
  })

  test('versions compare as numeric tuples, not strings or sums', () => {
    const high = versioned('a', [2, 0])
    const low = versioned('z', [1, 999])
    expect(compareRecordOps(high, low, VERSIONED)).toEqual({ status: 'apply' })
    expect(compareRecordOps(low, high, VERSIONED)).toEqual({ status: 'noop' })
    // '10' sorts before '9' as a string.
    expect(compareRecordOps(versioned('a', [10]), versioned('z', [9]), VERSIONED).status).toBe(
      'apply',
    )
  })

  test('a longer tuple extending an equal prefix is greater', () => {
    expect(compareRecordOps(versioned('a', [1, 0]), versioned('z', [1]), VERSIONED).status).toBe(
      'apply',
    )
    expect(compareRecordOps(versioned('z', [1]), versioned('a', [1, 0]), VERSIONED).status).toBe(
      'noop',
    )
  })

  test('the version decides, not the hlc', () => {
    const newerStampLowerVersion = versioned('z', [1], { hlc: hlcAt(1000) })
    const olderStampHigherVersion = versioned('a', [2], { hlc: hlcAt(0) })
    expect(
      compareRecordOps(olderStampHigherVersion, newerStampLowerVersion, VERSIONED).status,
    ).toBe('apply')
  })

  test('different operations at one monotonic version are reported', () => {
    const base = {
      issuer: 'did:key:owner',
      claim: {
        type: 'credential.manifest',
        id: 'manifest-1',
        owner: 'did:key:owner',
        hlc: '2026-09-26T00:00:00.000Z:00000000:node',
        payloadDigest: 'digest',
        deleted: false,
        meta: { epoch: 2, sequence: 7 },
      },
    }
    const stored: VerifiedRecordOp = { ...base, opHash: 'a' }
    const incoming: VerifiedRecordOp = {
      ...base,
      opHash: 'b',
      claim: { ...base.claim, payloadDigest: 'digest-b' },
    }
    const policy: MergePolicy = {
      kind: 'monotonic',
      version: (op) => [Number(op.meta.epoch), Number(op.meta.sequence)],
    }
    const conflict = { storedOpHash: 'a', incomingOpHash: 'b' }
    expect(compareRecordOps(incoming, stored, policy)).toEqual({
      status: higherContent(incoming, stored) ? 'apply' : 'noop',
      reason: 'equal-version-conflict',
      conflict,
    })
    expect(compareRecordOps(stored, incoming, policy)).toEqual({
      status: higherContent(stored, incoming) ? 'apply' : 'noop',
      reason: 'equal-version-conflict',
      conflict: { storedOpHash: 'b', incomingOpHash: 'a' },
    })
    expect(compareRecordOps(stored, stored, policy)).toEqual({ status: 'noop' })
  })

  test('a fork hook keeps both operations at one version, and is not asked about the same op', () => {
    const asked: Array<[string, string]> = []
    const onEqual = (incoming: VerifiedRecordOp, stored: VerifiedRecordOp) => {
      asked.push([incoming.opHash, stored.opHash])
      return 'fork' as const
    }
    const a = versioned('a', [3])
    const b = versioned('b', [3])
    expect(compareRecordOps(b, a, VERSIONED, onEqual)).toEqual({
      status: 'fork',
      reason: 'equal-version-fork',
      conflict: { storedOpHash: 'a', incomingOpHash: 'b' },
    })
    expect(compareRecordOps(a, b, VERSIONED, onEqual).status).toBe('fork')
    expect(compareRecordOps(a, a, VERSIONED, onEqual)).toEqual({ status: 'noop' })
    expect(asked).toEqual([
      ['b', 'a'],
      ['a', 'b'],
    ])
  })

  test('a hook answering resolve falls back to the greater content digest', () => {
    const resolve = (): EqualVersionDecision => 'resolve'
    const a = versioned('a', [3])
    const b = versioned('b', [3])
    expect(compareRecordOps(b, a, VERSIONED, resolve).status).toBe(
      higherContent(b, a) ? 'apply' : 'noop',
    )
    expect(compareRecordOps(a, b, VERSIONED, resolve).status).toBe(
      higherContent(a, b) ? 'apply' : 'noop',
    )
  })

  test('the hook is not consulted across different versions', () => {
    const onEqual = (): EqualVersionDecision => {
      throw new Error('hook consulted')
    }
    expect(compareRecordOps(versioned('a', [4]), versioned('b', [3]), VERSIONED, onEqual)).toEqual({
      status: 'apply',
    })
  })

  test.each([
    ['a NaN component', [Number.NaN]],
    ['an infinite component', [Number.POSITIVE_INFINITY]],
    ['a non-number component', ['2']],
    ['a non-array', 2],
  ])('an incoming version with %s is rejected', (_label, version) => {
    const incoming = op('z', { meta: { version } })
    expect(compareRecordOps(incoming, versioned('a', [1]), VERSIONED)).toEqual({
      status: 'reject',
      reason: 'version-invalid',
    })
  })

  test('a version function that throws rejects the incoming op', () => {
    const policy: MergePolicy = {
      kind: 'monotonic',
      version: (claim) => {
        if (claim.meta.version == null) throw new Error('no version')
        return claim.meta.version as ReadonlyArray<number>
      },
    }
    expect(compareRecordOps(op('z'), versioned('a', [1]), policy).status).toBe('reject')
  })

  test('a stored op with an invalid version yields to a valid one', () => {
    const stored = op('z', { meta: { version: [Number.NaN] } })
    expect(compareRecordOps(versioned('a', [1]), stored, VERSIONED)).toEqual({
      status: 'apply',
      reason: 'stored-version-invalid',
    })
  })
})

describe('immutable', () => {
  test('an identical duplicate is a no-op', () => {
    const stored = op('a')
    expect(compareRecordOps(stored, stored, IMMUTABLE)).toEqual({ status: 'noop' })
  })

  test.each([
    ['payload', { payloadDigest: 'digest-2' }],
    ['owner', { owner: 'did:key:other' }],
    ['meta', { meta: { keyID: 'other' } }],
    ['deletion flag', { deleted: true }],
    ['stamp alone', { hlc: hlcAt(-5000) }],
  ])(
    'a different %s under one id settles on the greater content digest and reports it',
    (_label, change) => {
      const low = op('a')
      const high = op('b', change)
      expect(compareRecordOps(high, low, IMMUTABLE)).toEqual({
        status: higherContent(high, low) ? 'apply' : 'noop',
        reason: 'immutable-conflict',
        conflict: { storedOpHash: 'a', incomingOpHash: 'b' },
      })
      expect(compareRecordOps(low, high, IMMUTABLE)).toEqual({
        status: higherContent(low, high) ? 'apply' : 'noop',
        reason: 'immutable-conflict',
        conflict: { storedOpHash: 'b', incomingOpHash: 'a' },
      })
      for (const order of [
        [low, high],
        [high, low],
      ]) {
        expect(replay(order, IMMUTABLE)).toEqual({
          rows: { 'record-1': [higherContent(high, low) ? 'b' : 'a'] },
          conflicts: ['a|b'],
          reports: 1,
        })
      }
    },
  )
})

// A seeded generator, so a failing permutation replays exactly.
function mulberry32(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function arrival(ops: Array<VerifiedRecordOp>, random: () => number): Array<VerifiedRecordOp> {
  const list = [...ops]
  const duplicates = Math.floor(random() * ops.length) + 1
  for (let i = 0; i < duplicates; i++) {
    list.push(ops[Math.floor(random() * ops.length)] as VerifiedRecordOp)
  }
  for (let i = list.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1))
    ;[list[i], list[j]] = [list[j] as VerifiedRecordOp, list[i] as VerifiedRecordOp]
  }
  return list
}

type Terminal = { rows: Record<string, Array<string>>; conflicts: Array<string> }

/**
 * What a store holds after a sequence of arrivals. Each id retains a set of branches — one,
 * unless a fork hook keeps several. An incoming op must beat every retained branch or fork
 * with it; losing to any of them drops it.
 */
function replay(
  arrivals: Array<VerifiedRecordOp>,
  policy: MergePolicy,
  onEqual?: (incoming: VerifiedRecordOp, stored: VerifiedRecordOp) => EqualVersionDecision,
): Terminal & { reports: number } {
  const rows = new Map<string, Array<VerifiedRecordOp>>()
  const conflicts = new Set<string>()
  let reports = 0
  for (const incoming of arrivals) {
    const retained = rows.get(incoming.claim.id)
    if (retained === undefined) {
      rows.set(incoming.claim.id, [incoming])
      continue
    }
    const decisions: Array<MergeDecision> = retained.map((stored) =>
      compareRecordOps(incoming, stored, policy, onEqual),
    )
    for (const decision of decisions) {
      if (decision.conflict !== undefined) {
        reports++
        const pair = [decision.conflict.storedOpHash, decision.conflict.incomingOpHash].sort()
        conflicts.add(pair.join('|'))
      }
    }
    if (decisions.some((d) => d.status === 'noop' || d.status === 'reject')) {
      continue
    }
    rows.set(incoming.claim.id, [
      ...retained.filter((_, index) => decisions[index]?.status === 'fork'),
      incoming,
    ])
  }
  const terminal: Record<string, Array<string>> = {}
  for (const [id, retained] of [...rows].sort(([a], [b]) => (a < b ? -1 : 1))) {
    terminal[id] = retained.map((stored) => stored.opHash).sort()
  }
  return { rows: terminal, conflicts: [...conflicts].sort(), reports }
}

function expectConvergence(
  ops: Array<VerifiedRecordOp>,
  policy: MergePolicy,
  expected: Terminal,
  onEqual?: (incoming: VerifiedRecordOp, stored: VerifiedRecordOp) => EqualVersionDecision,
): void {
  for (let seed = 1; seed <= 200; seed++) {
    const { rows, conflicts } = replay(arrival(ops, mulberry32(seed)), policy, onEqual)
    expect({ seed, rows, conflicts }).toEqual({ seed, ...expected })
  }
}

describe('every arrival order converges', () => {
  test('lww, with equal stamps, deletes and several ids', () => {
    const ops = [
      op('h1', { id: 'r1', hlc: hlcAt(0) }),
      op('h2', { id: 'r1', hlc: hlcAt(5) }),
      op('h3', { id: 'r1', hlc: hlcAt(5), deleted: true }),
      op('h0', { id: 'r1', hlc: hlcAt(5, 0, 'node') }),
      op('h4', { id: 'r2', hlc: hlcAt(1, 3) }),
      op('h5', { id: 'r2', hlc: hlcAt(1, 12), deleted: true }),
      op('h6', { id: 'r2', hlc: hlcAt(1, 12, 'node-b') }),
      op('h7', { id: 'r3', hlc: hlcAt(-100_000) }),
    ]
    const r1 = [ops[1], ops[2], ops[3]].reduce((best, item) =>
      higherContent(item as VerifiedRecordOp, best as VerifiedRecordOp) ? item : best,
    ) as VerifiedRecordOp
    expectConvergence(ops, LWW, {
      rows: { r1: [r1.opHash], r2: ['h6'], r3: ['h7'] },
      conflicts: [],
    })
  })

  test('monotonic, with equal-version conflicts', () => {
    const ops = [
      versioned('m1', [1, 999], { id: 'r1' }),
      versioned('m2', [2, 0], { id: 'r1' }),
      versioned('m3', [2, 0], { id: 'r1' }),
      versioned('m4', [2, 0], { id: 'r1', deleted: true }),
      versioned('m5', [1, 0], { id: 'r2' }),
      versioned('m6', [1, 0], { id: 'r2' }),
      versioned('m7', [0, 5], { id: 'r3' }),
    ]
    const r1 = ops
      .slice(1, 4)
      .reduce((best, item) =>
        higherContent(item as VerifiedRecordOp, best as VerifiedRecordOp) ? item : best,
      ) as VerifiedRecordOp
    const r2 = higherContent(ops[5] as VerifiedRecordOp, ops[4] as VerifiedRecordOp) ? 'm6' : 'm5'
    const expected = { r1: [r1.opHash], r2: [r2], r3: ['m7'] }
    for (let seed = 1; seed <= 200; seed++) {
      const { rows, conflicts } = replay(arrival(ops, mulberry32(seed)), VERSIONED)
      expect({ seed, rows }).toEqual({ seed, rows: expected })
      // Which pairs meet depends on arrival order, but every order reports some conflict at
      // each contested version and never one at an uncontested version.
      expect(conflicts.some((pair) => pair.startsWith('m5|m6'))).toBe(true)
      expect(conflicts.some((pair) => /m[234]\|m[234]/.test(pair))).toBe(true)
      expect(conflicts.every((pair) => !pair.includes('m1') && !pair.includes('m7'))).toBe(true)
    }
  })

  test('two conflicting monotonic ops converge on the greater content digest with one report per order', () => {
    const low = versioned('a', [2, 7])
    const high = versioned('b', [2, 7])
    for (const order of [
      [low, high],
      [high, low],
    ]) {
      expect(replay(order, VERSIONED)).toEqual({
        rows: { 'record-1': [higherContent(high, low) ? 'b' : 'a'] },
        conflicts: ['a|b'],
        reports: 1,
      })
    }
  })

  test('a fork hook retains the same branch set under every order', () => {
    const ops = [
      versioned('k1', [1], { id: 'key' }),
      versioned('k2a', [2], { id: 'key' }),
      versioned('k2b', [2], { id: 'key' }),
      versioned('k2c', [2], { id: 'key' }),
    ]
    expectConvergence(
      ops,
      VERSIONED,
      { rows: { key: ['k2a', 'k2b', 'k2c'] }, conflicts: ['k2a|k2b', 'k2a|k2c', 'k2b|k2c'] },
      FORK_ON_EQUAL,
    )
    // A later version supersedes every branch.
    expectConvergence(
      [...ops, versioned('k3', [3], { id: 'key' })],
      VERSIONED,
      { rows: { key: ['k3'] }, conflicts: expect.any(Array) as unknown as Array<string> },
      FORK_ON_EQUAL,
    )
  })

  test('a fork hook over two ops keeps both under both orders', () => {
    const a = versioned('a', [2])
    const b = versioned('b', [2])
    expect(replay([a, b], VERSIONED, FORK_ON_EQUAL).rows).toEqual({ 'record-1': ['a', 'b'] })
    expect(replay([b, a], VERSIONED, FORK_ON_EQUAL).rows).toEqual({ 'record-1': ['a', 'b'] })
  })

  test('immutable, with different ops under a natural key', () => {
    // Keyed like a revocation, by (keyID, recipientDID) rather than a payload digest, so
    // different payloads, owners and flags can meet under one id.
    const ops = [
      op('i1', { id: 'key-1:bob', payloadDigest: 'p1', hlc: hlcAt(0) }),
      op('i2', { id: 'key-1:bob', payloadDigest: 'p2', hlc: hlcAt(9) }),
      op('i0', { id: 'key-1:bob', owner: 'did:key:other', hlc: hlcAt(-9) }),
      op('i4', { id: 'key-1:bob', deleted: true }),
      op('i3', { id: 'key-2:bob', payloadDigest: 'p3' }),
    ]
    for (let seed = 1; seed <= 200; seed++) {
      const { rows, conflicts } = replay(arrival(ops, mulberry32(seed)), IMMUTABLE)
      expect({ seed, rows }).toEqual({ seed, rows: { 'key-1:bob': ['i4'], 'key-2:bob': ['i3'] } })
      expect(conflicts.length).toBeGreaterThan(0)
      expect(conflicts.every((pair) => !pair.includes('i3'))).toBe(true)
    }
  })

  test('an asymmetric fork hook splits peers, which a two-order replay detects', () => {
    // Forks only when the incoming op has the greater opHash: (b, a) forks, (a, b) resolves.
    const asymmetric = (incoming: VerifiedRecordOp, stored: VerifiedRecordOp) =>
      incoming.opHash > stored.opHash ? ('fork' as const) : ('resolve' as const)
    const a = versioned('a', [2])
    const b = versioned('b', [2])
    const forward = replay([a, b], VERSIONED, asymmetric).rows
    const backward = replay([b, a], VERSIONED, asymmetric).rows
    expect(forward).toEqual({ 'record-1': ['a', 'b'] })
    expect(backward).toEqual({ 'record-1': [higherContent(a, b) ? 'a' : 'b'] })
    expect(forward).not.toEqual(backward)
  })
})
