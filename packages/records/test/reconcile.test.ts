import { normalizeDID, randomIdentity, type SigningIdentity } from '@kokuin/token'
import { blake3 } from '@noble/hashes/blake3.js'
import { fromUTF, toB64U } from '@sozai/codec'
import { HLC } from '@sozai/hlc'
import { describe, expect, test } from 'vitest'

import {
  advanceRecordPull,
  applyRecordChunk,
  beginRecordPull,
  fingerprintRange,
  MAX_RECORD_ID_LENGTH,
  nextRequesterSteps,
  RANGE_LEAF_THRESHOLD,
  type RangeBounds,
  type RangeLeaf,
  type RangeLeafList,
  type RangeSummary,
  type RecordPullState,
  RecordRangeError,
  type RecordStoreAdapter,
  type RecordTypeDefinition,
  type RequesterStep,
  rangeContains,
  rangeLeaf,
  rangePosition,
  recordPayloadDigest,
  type SignedRecord,
  signRecordOp,
  splitRange,
  summarizeRange,
  verifySignedRecord,
} from '../src/index.js'
import { decisionOf } from './decision-fixture.js'

type RangeResponse = RangeSummary | RangeLeafList

const TYPE = 'credential.entry'
const OWNER = 'owner'
const position = (id: string) => rangePosition({ owner: OWNER, id })
const WHOLE: RangeBounds = { type: TYPE, lower: null, upper: null }

function hashOf(seed: string): string {
  return toB64U(blake3(fromUTF(seed), { dkLen: 32 }))
}

function orderAt(offset: number): string {
  return HLC.serialize({ wallTime: 1_790_000_000_000 + offset, counter: 0, nodeID: 'node' })
}

function leafAt(index: number, type = TYPE): RangeLeaf {
  return {
    type,
    owner: OWNER,
    id: `id-${hashOf(`id-${type}-${index}`).slice(0, 12)}`,
    opHash: hashOf(`op-${type}-${index}`),
    contentDigest: hashOf(`op-${type}-${index}`),
    signers: [],
    order: orderAt(index),
  }
}

function leaves(count: number, type = TYPE): Array<RangeLeaf> {
  return Array.from({ length: count }, (_, index) => leafAt(index, type))
}

function key(entry: { type: string; owner: string; id: string }): string {
  return JSON.stringify([entry.type, entry.owner, entry.id])
}

test('a directional pass stops with no pull when R has an extra row', () => {
  const s: Array<RangeLeaf> = [
    {
      type: 'credential.entry',
      owner: OWNER,
      id: 'shared',
      opHash: hashOf('a'),
      contentDigest: hashOf('a'),
      signers: [],
      order: '1',
    },
  ]
  const r: Array<RangeLeaf> = [
    ...s,
    {
      type: 'credential.entry',
      owner: OWNER,
      id: 'r-only',
      opHash: hashOf('b'),
      contentDigest: hashOf('b'),
      signers: [],
      order: '1',
    },
  ]
  const bounds = { type: 'credential.entry', lower: null, upper: null }
  const steps = nextRequesterSteps(r, { bounds, leaves: s })
  expect(steps).toEqual([])
})

describe('the requester answers a summary', () => {
  const rows = leaves(40)

  test('matches when it holds the same records in the range', () => {
    const summary = summarizeRange(rows, WHOLE)
    expect(nextRequesterSteps([...rows].reverse(), summary)).toEqual([
      { answer: 'matches', bounds: WHOLE },
    ])
  })

  test('is empty when it holds nothing in the range, whatever it holds elsewhere', () => {
    const sorted = [...rows].sort((left, right) => (left.id < right.id ? -1 : 1))
    const bounds: RangeBounds = {
      type: TYPE,
      lower: rangePosition(sorted[19] as RangeLeaf),
      upper: null,
    }
    const summary = summarizeRange(rows, bounds)
    const local = [...sorted.slice(0, 20), ...leaves(5, 'credential.key')]
    expect(nextRequesterSteps(local, summary)).toEqual([{ answer: 'empty', bounds }])
  })

  test('differs when it holds an older op of one record', () => {
    const stale = rows.map((row, index) =>
      index === 7 ? { ...row, opHash: hashOf('stale'), order: orderAt(-1) } : row,
    )
    expect(nextRequesterSteps(stale, summarizeRange(rows, WHOLE))).toEqual([
      { answer: 'differs', bounds: WHOLE },
    ])
  })

  test('differs when it holds a record the responder lacks', () => {
    expect(nextRequesterSteps([...rows, leafAt(99)], summarizeRange(rows, WHOLE))).toEqual([
      { answer: 'differs', bounds: WHOLE },
    ])
  })

  test('matches a range the responder holds nothing in, since there is nothing to pull', () => {
    expect(nextRequesterSteps(rows, summarizeRange([], WHOLE))).toEqual([
      { answer: 'matches', bounds: WHOLE },
    ])
  })

  test('reads its own records only from the range and type it was asked about', () => {
    const summary = summarizeRange(rows, WHOLE)
    expect(nextRequesterSteps([...rows, ...leaves(3, 'credential.key')], summary)).toEqual([
      { answer: 'matches', bounds: WHOLE },
    ])
  })
})

describe('the requester picks what to fetch from a leaf list', () => {
  const held: RangeLeaf = {
    type: TYPE,
    owner: OWNER,
    id: 'held',
    opHash: hashOf('held'),
    contentDigest: hashOf('held'),
    signers: [],
    order: orderAt(5),
  }

  function fetched(local: Array<RangeLeaf>, listed: Array<RangeLeaf>): Array<RequesterStep> {
    return nextRequesterSteps(local, { bounds: WHOLE, leaves: listed })
  }

  test('fetches a record it lacks', () => {
    expect(fetched([], [held])).toEqual([{ get: [{ type: TYPE, owner: OWNER, id: 'held' }] }])
  })

  test('fetches a newer order the responder alone holds', () => {
    const newer = { ...held, opHash: hashOf('newer'), order: orderAt(6) }
    expect(fetched([held], [newer])).toEqual([{ get: [{ type: TYPE, owner: OWNER, id: 'held' }] }])
  })

  test('fetches a survivor reissue only when its ordinary order is later', () => {
    const removed = { ...held, order: orderAt(5) }
    const reissue = { ...held, opHash: hashOf('survivor-reissue'), order: orderAt(10) }
    expect(nextRequesterSteps([removed], { bounds: WHOLE, leaves: [reissue] })).toEqual([
      { get: [{ type: TYPE, owner: OWNER, id: held.id }] },
    ])
    expect(nextRequesterSteps([reissue], { bounds: WHOLE, leaves: [removed] })).toEqual([])
  })

  test('fetches a re-added device op newer than an old survivor reissue', () => {
    const reissue = {
      ...held,
      issuer: 'did:key:survivor',
      supersedesSigner: 'did:key:removed',
      order: orderAt(5),
    }
    const readded = {
      ...held,
      issuer: 'did:key:removed',
      opHash: hashOf('readded-device-op'),
      order: orderAt(6),
    }
    expect(fetched([reissue], [readded])).toEqual([
      { get: [{ type: TYPE, owner: OWNER, id: held.id }] },
    ])
  })

  test('does not fetch the same op, or an older order', () => {
    expect(fetched([held], [held])).toEqual([])
    const older = { ...held, opHash: hashOf('older'), order: orderAt(4) }
    expect(fetched([held], [older])).toEqual([])
  })

  test('at an equal order, fetches only the op the policy prefers: the greater op hash', () => {
    const [low, middle, high] = [hashOf('x'), hashOf('y'), hashOf('z')].sort() as [
      string,
      string,
      string,
    ]
    const mine = { ...held, opHash: middle, contentDigest: middle }
    const greater = { ...held, opHash: high, contentDigest: high }
    const lesser = { ...held, opHash: low, contentDigest: low }
    expect(fetched([mine], [greater])).toEqual([
      { get: [{ type: TYPE, owner: OWNER, id: 'held' }] },
    ])
    expect(fetched([mine], [lesser])).toEqual([])
  })

  test('ignores listed leaves outside the range it asked about', () => {
    const bounds: RangeBounds = { type: TYPE, lower: position('m'), upper: position('p') }
    const listed = [
      { ...held, id: 'a' },
      { ...held, id: 'n' },
      { ...held, id: 'z' },
      { ...held, id: 'n2', type: 'credential.key' },
    ]
    expect(nextRequesterSteps([], { bounds, leaves: listed })).toEqual([
      { get: [{ type: TYPE, owner: OWNER, id: 'n' }] },
    ])
  })
})

test('a numeric-string version pulls the numeric winner from the responder', async () => {
  const identity = randomIdentity()
  const owner = normalizeDID(identity.id)
  const key = { type: 'numeric.record', owner, id: 'shared' }
  const hlc = HLC.serialize({ wallTime: Date.now(), counter: 0, nodeID: 'numeric' })
  const policy = {
    kind: 'monotonic' as const,
    version: (claim: { meta: Record<string, unknown> }) => [Number(claim.meta.version)],
  }
  const signedVersion = async (version: string) => {
    const payload = fromUTF(version)
    const claim = {
      ...key,
      hlc,
      payloadDigest: recordPayloadDigest(payload),
      deleted: false,
      meta: { version },
    }
    return { ...key, hlc, payload, ...(await signRecordOp(identity, claim)) }
  }
  const local = await signedVersion('2')
  const remote = await signedVersion('10')
  const localLeaf = rangeLeaf(decisionOf(local), policy)
  const remoteLeaf = rangeLeaf(decisionOf(remote), policy)
  if (localLeaf === null || remoteLeaf === null) throw new Error('missing numeric leaf')

  const result = runPass([localLeaf], [remoteLeaf], [key.type])
  expect(result.state.complete).toBe(true)
  expect(result.fetched).toEqual([JSON.stringify([key.type, owner, key.id])])
})

/**
 * The responder side of a pass, scanning its visible rows on every request: a summary per
 * type, a split or leaf list for a range that differs, and the records themselves for a range
 * the requester holds nothing in.
 */
function responder(visible: ReadonlyArray<RangeLeaf>) {
  return {
    sent: [] as Array<unknown>,
    begin(types: ReadonlyArray<string>): Array<RangeResponse> {
      const out = types.map((type) => summarizeRange(visible, { type, lower: null, upper: null }))
      this.sent.push(out)
      return out
    },
    answer(steps: ReadonlyArray<RequesterStep>) {
      const ranges: Array<RangeResponse> = []
      const records: Array<RangeLeaf> = []
      for (const step of steps) {
        if (!('answer' in step)) {
          continue
        }
        if (step.answer === 'differs') {
          ranges.push(...splitRange(visible, step.bounds, RANGE_LEAF_THRESHOLD))
        } else if (step.answer === 'empty') {
          records.push(...visible.filter((row) => rangeContains(step.bounds, row)))
        }
      }
      this.sent.push(ranges, records)
      return { ranges, records }
    },
  }
}

type PassResult = {
  state: RecordPullState
  roundTrips: number
  fetched: Array<string>
  delivered: Array<string>
  leafLists: number
  requests: Array<Array<RequesterStep>>
}

/** Drive one pull pass to completion; the final `records/get` counts as one more round trip. */
function runPass(
  local: ReadonlyArray<RangeLeaf>,
  visible: ReadonlyArray<RangeLeaf>,
  types: ReadonlyArray<string> = [TYPE],
): PassResult & { sent: Array<unknown> } {
  const peer = responder(visible)
  let state = beginRecordPull(types)
  let responses = peer.begin(types)
  let roundTrips = 1
  let leafLists = 0
  const delivered: Array<string> = []
  const requests: Array<Array<RequesterStep>> = []
  for (;;) {
    const outgoing: Array<RequesterStep> = []
    for (const response of responses) {
      if ('leaves' in response) {
        leafLists += 1
      }
      const advanced = advanceRecordPull(state, local, response)
      state = advanced.state
      outgoing.push(...advanced.steps)
    }
    if (outgoing.length > 0) {
      requests.push(outgoing)
    }
    const answers = outgoing.filter((step) => 'answer' in step && step.answer !== 'matches')
    if (answers.length === 0) {
      break
    }
    roundTrips += 1
    const reply = peer.answer(answers)
    responses = reply.ranges
    delivered.push(...reply.records.map(key))
  }
  if (state.requested.length > 0) {
    roundTrips += 1
  }
  return {
    state,
    roundTrips,
    fetched: state.requested.map(key),
    delivered,
    leafLists,
    requests,
    sent: peer.sent,
  }
}

type Scenario = 'in-sync' | 'one-stale' | 'requester-empty' | 'requester-extra'

function scenario(count: number, kind: Scenario) {
  const visible = leaves(count)
  const sorted = [...visible].sort((left, right) => (left.id < right.id ? -1 : 1))
  const middle = sorted[Math.floor(count / 2)] as RangeLeaf
  switch (kind) {
    case 'in-sync':
      return { visible, local: [...visible], fetch: [], deliver: [] }
    case 'one-stale':
      return {
        visible,
        local: visible.map((row) =>
          row === middle ? { ...row, opHash: hashOf(`stale-${row.id}`), order: orderAt(-1) } : row,
        ),
        fetch: [key(middle)],
        deliver: [],
      }
    case 'requester-empty':
      return { visible, local: [], fetch: [], deliver: visible.map(key) }
    case 'requester-extra':
      return {
        visible,
        local: [...visible, { ...leafAt(count + 1), id: `${middle.id}-r-only` }],
        fetch: [],
        deliver: [],
      }
  }
}

describe('a pull pass with the measured configuration', () => {
  // Round trips include the opening `records/sync` and the closing `records/get`.
  const expected: Record<Scenario, Record<number, number>> = {
    'in-sync': { 10: 1, 100: 1, 1000: 1 },
    'one-stale': { 10: 3, 100: 4, 1000: 5 },
    'requester-empty': { 10: 2, 100: 2, 1000: 2 },
    'requester-extra': { 10: 2, 100: 3, 1000: 4 },
  }

  for (const kind of ['in-sync', 'one-stale', 'requester-empty', 'requester-extra'] as const) {
    test.each([10, 100, 1000])(`${kind} at %i rows pulls exactly the diff`, (count) => {
      const { visible, local, fetch, deliver } = scenario(count, kind)
      const result = runPass(local, visible)
      expect(result.state.complete).toBe(true)
      expect(result.state.pending).toEqual([])
      // The guard: the pass finds exactly the diff, nothing vacuous and nothing extra.
      expect([...result.fetched].sort()).toEqual([...fetch].sort())
      expect([...result.delivered].sort()).toEqual([...deliver].sort())
      expect(result.roundTrips).toBe(expected[kind][count])
      if (kind === 'one-stale' || kind === 'requester-extra') {
        expect(result.leafLists).toBeGreaterThan(0)
      }
    })
  }

  test('an extra row in the requester keeps its range differing but asks for nothing', () => {
    const { visible, local } = scenario(1000, 'requester-extra')
    const result = runPass(local, visible)
    const answers = result.requests.flat()
    expect(answers.some((step) => 'answer' in step && step.answer === 'differs')).toBe(true)
    expect(answers.some((step) => 'get' in step)).toBe(false)
    expect(result.state).toEqual({ pending: [], requested: [], complete: true })
  })

  test('an empty requester gets every visible record of each type in one round trip', () => {
    const entries = leaves(1000)
    const keys = leaves(40, 'credential.key')
    const hidden = leaves(30, 'credential.wrapping')
    // The responder filters to what the requester may see before it answers.
    const visible = [...entries, ...keys]
    const result = runPass([], visible, ['credential.entry', 'credential.key'])
    expect(result.roundTrips).toBe(2)
    expect(result.requests).toEqual([
      [
        { answer: 'empty', bounds: { type: 'credential.entry', lower: null, upper: null } },
        { answer: 'empty', bounds: { type: 'credential.key', lower: null, upper: null } },
      ],
    ])
    expect(result.leafLists).toBe(0)
    expect(result.state).toEqual({ pending: [], requested: [], complete: true })
    expect([...result.delivered].sort()).toEqual(visible.map(key).sort())
    expect(result.delivered.some((entry) => hidden.map(key).includes(entry))).toBe(false)
  })

  test('the requester sends only answers and ids the responder sent it', () => {
    for (const kind of ['one-stale', 'requester-extra', 'requester-empty'] as const) {
      const { visible, local } = scenario(1000, kind)
      const result = runPass(local, visible)
      const fromResponder = new Set<string>()
      const collect = (value: unknown): void => {
        if (typeof value === 'string') {
          fromResponder.add(value)
        } else if (Array.isArray(value)) {
          value.forEach(collect)
        } else if (value !== null && typeof value === 'object') {
          Object.values(value).forEach(collect)
        }
      }
      collect(result.sent)
      const requesterOnly = new Set<string>()
      for (const row of local) {
        if (!visible.some((shown) => shown.id === row.id && shown.opHash === row.opHash)) {
          requesterOnly.add(row.opHash)
          if (!visible.some((shown) => shown.id === row.id)) {
            requesterOnly.add(row.id)
          }
        }
      }
      const localFingerprints = new Set([fingerprintRange(local)])

      for (const step of result.requests.flat()) {
        if ('answer' in step) {
          expect(Object.keys(step).sort()).toEqual(['answer', 'bounds'])
          expect(['matches', 'differs', 'empty']).toContain(step.answer)
          expect(Object.keys(step.bounds).sort()).toEqual(['lower', 'type', 'upper'])
          for (const bound of [step.bounds.lower, step.bounds.upper]) {
            if (bound !== null) {
              expect(fromResponder.has(bound)).toBe(true)
            }
          }
          continue
        }
        for (const entry of step.get) {
          expect(Object.keys(entry).sort()).toEqual(['id', 'owner', 'type'])
          expect(fromResponder.has(entry.id)).toBe(true)
        }
      }
      for (const entry of result.state.requested) {
        expect(fromResponder.has(entry.id)).toBe(true)
      }
      const outgoing = JSON.stringify([result.requests, result.state.requested])
      for (const secret of [...requesterOnly, ...localFingerprints]) {
        expect(outgoing.includes(secret)).toBe(false)
      }
    }
  })
})

describe('advanceRecordPull', () => {
  test('begins with one whole range per distinct type', () => {
    expect(beginRecordPull(['b.type', 'a.type', 'b.type'])).toEqual({
      pending: [
        { type: 'a.type', lower: null, upper: null },
        { type: 'b.type', lower: null, upper: null },
      ],
      requested: [],
      complete: false,
    })
    expect(beginRecordPull([])).toEqual({ pending: [], requested: [], complete: true })
  })

  test('narrows a pending range as the split arrives, child by child', () => {
    const rows = leaves(100)
    const local = rows.map((row, index) =>
      index === 0 ? { ...row, opHash: hashOf('stale-0'), order: orderAt(-1) } : row,
    )
    const state = advanceRecordPull(
      beginRecordPull([TYPE]),
      local,
      summarizeRange(rows, WHOLE),
    ).state
    expect(state.pending).toEqual([WHOLE])
    const children = splitRange(rows, WHOLE, RANGE_LEAF_THRESHOLD) as Array<RangeSummary>
    const [first, second] = children as [RangeSummary, RangeSummary]
    const afterFirst = advanceRecordPull(state, local, first).state
    expect(afterFirst.complete).toBe(false)
    expect(afterFirst.pending).toContainEqual({
      type: TYPE,
      lower: first.bounds.upper,
      upper: null,
    })
    const afterSecond = advanceRecordPull(afterFirst, local, second).state
    expect(afterSecond.pending).toContainEqual({
      type: TYPE,
      lower: second.bounds.upper,
      upper: null,
    })
    expect(afterSecond.pending).not.toContainEqual({
      type: TYPE,
      lower: first.bounds.upper,
      upper: null,
    })
  })

  test('refuses a response for a range it is not waiting on', () => {
    const rows = leaves(40)
    const state = beginRecordPull([TYPE])
    expect(() =>
      advanceRecordPull(
        state,
        [],
        summarizeRange(rows, { type: 'credential.key', lower: null, upper: null }),
      ),
    ).toThrow(RecordRangeError)
    expect(() =>
      advanceRecordPull(state, [], summarizeRange(rows, { type: TYPE, lower: 'a', upper: null })),
    ).toThrow(RecordRangeError)
    const done = advanceRecordPull(state, rows, summarizeRange(rows, WHOLE)).state
    expect(done.complete).toBe(true)
    expect(() => advanceRecordPull(done, rows, summarizeRange(rows, WHOLE))).toThrow(
      RecordRangeError,
    )
  })

  test('a listed id cannot be requested twice in one pass', () => {
    const [row] = leaves(1) as [RangeLeaf]
    const listed = { ...row, id: 'c' }
    const state: RecordPullState = {
      pending: [{ type: TYPE, lower: null, upper: null }],
      requested: [],
      complete: false,
    }
    const first = advanceRecordPull(state, [], {
      bounds: { type: TYPE, lower: null, upper: 'd' },
      leaves: [listed],
    })
    expect(first.state.requested).toEqual([{ type: TYPE, owner: OWNER, id: 'c' }])
    // The part holding `c` is answered; the same list again answers no pending range.
    expect(() =>
      advanceRecordPull(first.state, [], {
        bounds: { type: TYPE, lower: null, upper: 'd' },
        leaves: [listed],
      }),
    ).toThrow(RecordRangeError)
    // And a list for what remains ignores a leaf outside it.
    const rest = advanceRecordPull(first.state, [], {
      bounds: { type: TYPE, lower: 'd', upper: null },
      leaves: [listed],
    })
    expect(rest.state).toEqual({
      pending: [],
      requested: [{ type: TYPE, owner: OWNER, id: 'c' }],
      complete: true,
    })
  })

  test('refuses a leaf list longer than the threshold', () => {
    const listed = leaves(RANGE_LEAF_THRESHOLD + 1)
    expect(() => nextRequesterSteps([], { bounds: WHOLE, leaves: listed })).toThrow(
      RecordRangeError,
    )
    expect(() =>
      advanceRecordPull(beginRecordPull([TYPE]), [], { bounds: WHOLE, leaves: listed }),
    ).toThrow(RecordRangeError)
    expect(
      nextRequesterSteps([], { bounds: WHOLE, leaves: listed.slice(0, RANGE_LEAF_THRESHOLD) }),
    ).toHaveLength(1)
  })

  test('refuses a listed leaf with an id past the length bound', () => {
    const [row] = leaves(1) as [RangeLeaf]
    const long = { ...row, id: 'x'.repeat(MAX_RECORD_ID_LENGTH + 1) }
    expect(() => nextRequesterSteps([], { bounds: WHOLE, leaves: [long] })).toThrow(
      RecordRangeError,
    )
    const atBound = { ...row, id: 'x'.repeat(MAX_RECORD_ID_LENGTH) }
    expect(nextRequesterSteps([], { bounds: WHOLE, leaves: [atBound] })).toEqual([
      { get: [{ type: TYPE, owner: OWNER, id: atBound.id }] },
    ])
  })

  test('refuses a listed leaf whose op hash is not a canonical digest', () => {
    const [row] = leaves(1) as [RangeLeaf]
    for (const opHash of ['a', `${row.opHash}=`, toB64U(new Uint8Array(31))]) {
      expect(() =>
        advanceRecordPull(beginRecordPull([TYPE]), [], {
          bounds: WHOLE,
          leaves: [{ ...row, opHash }],
        }),
      ).toThrow(RecordRangeError)
    }
  })

  test('refuses a child reaching past the range it answers for', () => {
    const state: RecordPullState = {
      pending: [{ type: TYPE, lower: 'b', upper: 'm' }],
      requested: [],
      complete: false,
    }
    const past = { bounds: { type: TYPE, lower: 'b', upper: 'n' }, leaves: [] }
    expect(() => advanceRecordPull(state, [], past)).toThrow(RecordRangeError)
    const open = { bounds: { type: TYPE, lower: 'b', upper: null }, leaves: [] }
    expect(() => advanceRecordPull(state, [], open)).toThrow(RecordRangeError)
    const hollow = { bounds: { type: TYPE, lower: 'b', upper: 'b' }, leaves: [] }
    expect(() => advanceRecordPull(state, [], hollow)).toThrow(RecordRangeError)
  })

  test('asks for an id once, however many times it is listed', () => {
    const [row] = leaves(1) as [RangeLeaf]
    let state = beginRecordPull([TYPE])
    state = {
      ...state,
      pending: [
        { type: TYPE, lower: null, upper: 'm' },
        { type: TYPE, lower: 'm', upper: null },
      ],
    }
    const first = advanceRecordPull(state, [], {
      bounds: { type: TYPE, lower: null, upper: 'm' },
      leaves: [
        { ...row, id: 'a' },
        { ...row, id: 'a' },
      ],
    })
    expect(first.steps).toEqual([{ get: [{ type: TYPE, owner: OWNER, id: 'a' }] }])
    expect(first.state.requested).toEqual([{ type: TYPE, owner: OWNER, id: 'a' }])
  })
})

describe('fetched records still pass through apply', () => {
  const Now = Date.now()

  function memoryStore(initial: ReadonlyArray<SignedRecord> = []): RecordStoreAdapter {
    const rows = new Map(initial.map((record) => [key(record), record]))
    const store: RecordStoreAdapter = {
      transaction: async (fn) => await fn(store),
      get: async (keyValue) => {
        const record = rows.get(key(keyValue))
        return record === undefined ? null : decisionOf(record)
      },
      list: async (types) =>
        [...rows.values()].filter((record) => types.includes(record.type)).map(decisionOf),
      putCopy: async (record) => {
        rows.set(key(record), record)
      },
      pruneCopy: async () => {},
    }
    return store
  }

  async function makeRecord(
    identity: SigningIdentity,
    id: string,
    offsetMS: number,
    payload: Uint8Array,
  ): Promise<SignedRecord> {
    const owner = normalizeDID(identity.id)
    const hlc = HLC.serialize({ wallTime: Now + offsetMS, counter: 0, nodeID: identity.id })
    const signed = await signRecordOp(identity, {
      type: TYPE,
      id,
      owner,
      hlc,
      payloadDigest: recordPayloadDigest(payload),
      deleted: false,
      meta: {},
    })
    return { type: TYPE, id, owner, hlc, payload, ...signed }
  }

  const definition: RecordTypeDefinition = {
    type: TYPE,
    policy: { kind: 'lww' },
    dependsOn: [],
    authorize: async (op, ctx) => op.issuer === (ctx.stored?.owner ?? op.claim.owner),
    dependencies: () => [],
  }

  async function leavesOf(store: RecordStoreAdapter): Promise<Array<RangeLeaf>> {
    const out: Array<RangeLeaf> = []
    for (const record of await store.list([TYPE])) {
      const op = await verifySignedRecord(record.copies[0] as SignedRecord)
      const leaf = op === null ? null : rangeLeaf(record, definition.policy)
      if (leaf !== null) {
        out.push(leaf)
      }
    }
    return out
  }

  test('the requester pulls a newer op, applies it, and keeps its own newer one', async () => {
    const identity = randomIdentity()
    const sharedOld = await makeRecord(identity, 'shared', -2000, new Uint8Array([1]))
    const sharedNew = await makeRecord(identity, 'shared', -1000, new Uint8Array([2]))
    const mineOld = await makeRecord(identity, 'mine', -2000, new Uint8Array([3]))
    const mineNew = await makeRecord(identity, 'mine', -1000, new Uint8Array([4]))
    const theirs = await makeRecord(identity, 'theirs', -1500, new Uint8Array([5]))
    const responderStore = memoryStore([sharedNew, mineOld, theirs])
    const requesterStore = memoryStore([sharedOld, mineNew])

    const result = runPass(await leavesOf(requesterStore), await leavesOf(responderStore))
    expect([...result.fetched].sort()).toEqual([key(sharedNew), key(theirs)].sort())

    const fetchedRecords = (
      await Promise.all(result.state.requested.map((keyValue) => responderStore.get(keyValue)))
    ).flatMap((decision) => decision?.copies ?? [])
    const applied = await applyRecordChunk({
      records: fetchedRecords,
      store: requesterStore,
      types: new Map([[TYPE, definition]]),
      nowMS: Now,
      maxDriftMS: 60_000,
      receiveClock: () => {},
      resolveController: async () => null,
      verifyCapability: async () => false,
    })
    expect(applied).toMatchObject({ applied: 2, rejected: [], parked: [] })
    expect(
      (await requesterStore.get({ type: TYPE, owner: normalizeDID(identity.id), id: 'shared' }))
        ?.copies[0]?.opHash,
    ).toBe(sharedNew.opHash)
    expect(
      (await requesterStore.get({ type: TYPE, owner: normalizeDID(identity.id), id: 'theirs' }))
        ?.copies[0]?.opHash,
    ).toBe(theirs.opHash)
    expect(
      (await requesterStore.get({ type: TYPE, owner: normalizeDID(identity.id), id: 'mine' }))
        ?.copies[0]?.opHash,
    ).toBe(mineNew.opHash)

    // A second pass finds nothing left to pull.
    const again = runPass(await leavesOf(requesterStore), await leavesOf(responderStore))
    expect(again.state).toEqual({ pending: [], requested: [], complete: true })
  })
})
