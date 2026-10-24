import {
  assertListedLeaf,
  fingerprintRange,
  RANGE_LEAF_THRESHOLD,
  type RangeBounds,
  type RangeLeaf,
  type RangeLeafList,
  type RangeSummary,
  RecordRangeError,
  rangeContains,
  rangePosition,
} from './range.js'
import type { RecordKey } from './record.js'

/**
 * What a requester says about one range the responder summarized:
 * - `matches`: nothing to pull — it holds the same records, or the responder holds none;
 * - `differs`: split it further;
 * - `empty`: it holds nothing in the range, so the responder sends the range's records
 *   directly rather than splitting or listing it.
 */
export type RangeAnswer = 'matches' | 'differs' | 'empty'

/**
 * One message from requester to responder. It carries only answers, bounds and ids the
 * responder sent: never an id, hash or fingerprint of the requester's own.
 */
export type RequesterStep = { answer: RangeAnswer; bounds: RangeBounds } | { get: Array<RecordKey> }

/**
 * A requester's progress through one directional pass.
 *
 * `pending` holds the parts of the responder's key space still awaiting a summary or a leaf
 * list. `requested` holds every id asked for with `get`. The pass is `complete` once nothing
 * is pending: what is left is fetching `requested` and receiving the records of the ranges
 * answered `empty`, which the caller applies with `applyRecordChunk` like any other record.
 */
export type RecordPullState = {
  pending: Array<RangeBounds>
  requested: Array<RecordKey>
  complete: boolean
}

type RangeResponse = RangeSummary | RangeLeafList

function isLeafList(response: RangeResponse): response is RangeLeafList {
  return 'leaves' in response
}

/**
 * Whether the responder's decision is one this requester should fetch: it lacks the key,
 * the decision orders later, or the same content has a different held signer set.
 */
function prefersResponder(listed: RangeLeaf, held: RangeLeaf | undefined): boolean {
  if (held === undefined) {
    return true
  }
  if (listed.order !== held.order) {
    return listed.order > held.order
  }
  if (listed.contentDigest !== held.contentDigest) return listed.contentDigest > held.contentDigest
  return listed.opHash !== held.opHash
}

function answerFor(local: ReadonlyArray<RangeLeaf>, summary: RangeSummary): RangeAnswer {
  if (summary.count === 0) {
    return 'matches'
  }
  const mine = local.filter((leaf) => rangeContains(summary.bounds, leaf))
  if (mine.length === 0) {
    return 'empty'
  }
  // The fingerprint already carries the count.
  return fingerprintRange(mine) === summary.fingerprint ? 'matches' : 'differs'
}

/**
 * The requester's reply to one responder message about a range.
 *
 * A summary gets one answer. A leaf list gets one `get` for the listed records it lacks or
 * holds at an op the policy ranks lower, or nothing: a range can differ only because the
 * requester holds a record the responder lacks, and that record is the responder's own pass
 * to pull, not this one's. Listed leaves outside the range are ignored.
 *
 * @throws RecordRangeError when a leaf list is longer than `RANGE_LEAF_THRESHOLD`, or lists a
 * leaf `assertListedLeaf` refuses: a responder splits a larger range, so a longer list is
 * not one it would send.
 */
export function nextRequesterSteps(
  local: ReadonlyArray<RangeLeaf>,
  response: RangeResponse,
): Array<RequesterStep> {
  if (!isLeafList(response)) {
    return [{ answer: answerFor(local, response), bounds: { ...response.bounds } }]
  }
  if (response.leaves.length > RANGE_LEAF_THRESHOLD) {
    throw new RecordRangeError('Leaf list is longer than the leaf threshold')
  }
  for (const listed of response.leaves) {
    assertListedLeaf(listed)
  }
  const held = new Map(
    local
      .filter((leaf) => rangeContains(response.bounds, leaf))
      .map((leaf) => [rangePosition(leaf), leaf] as const),
  )
  const seen = new Set<string>()
  const get: Array<RecordKey> = []
  for (const listed of response.leaves) {
    if (
      rangeContains(response.bounds, listed) &&
      !seen.has(rangePosition(listed)) &&
      prefersResponder(listed, held.get(rangePosition(listed)))
    ) {
      seen.add(rangePosition(listed))
      get.push({ type: listed.type, owner: listed.owner, id: listed.id })
    }
  }
  return get.length === 0 ? [] : [{ get }]
}

/** A pass over the given types, each waiting on the responder's summary of its whole range. */
export function beginRecordPull(types: ReadonlyArray<string>): RecordPullState {
  const pending = [...new Set(types)].sort().map((type) => ({ type, lower: null, upper: null }))
  return { pending, requested: [], complete: pending.length === 0 }
}

/**
 * The index of the pending range a response answers for, which must start where it starts
 * and end inside it. A split's sub-ranges arrive in order, each narrowing the pending range
 * to what follows it.
 */
function pendingIndexFor(pending: ReadonlyArray<RangeBounds>, bounds: RangeBounds): number {
  const index = pending.findIndex(
    (range) => range.type === bounds.type && range.lower === bounds.lower,
  )
  if (index === -1) {
    throw new RecordRangeError('Response for a range the pass is not waiting on')
  }
  const range = pending[index] as RangeBounds
  const { lower, upper } = bounds
  const endsInside = range.upper === null ? true : upper !== null && upper <= range.upper
  if (!endsInside || (lower !== null && upper !== null && upper <= lower)) {
    throw new RecordRangeError('Response reaches outside the range the pass is waiting on')
  }
  return index
}

/**
 * Apply one responder message to a pass: narrow the pending range it answers for, wait on
 * any range answered `differs`, and add any fetched ids to `requested`. Returns the steps to
 * send back.
 *
 * @throws RecordRangeError when the message answers no pending range, reaches past it, or is
 * a leaf list `nextRequesterSteps` refuses.
 */
export function advanceRecordPull(
  state: RecordPullState,
  local: ReadonlyArray<RangeLeaf>,
  response: RangeResponse,
): { state: RecordPullState; steps: Array<RequesterStep> } {
  const index = pendingIndexFor(state.pending, response.bounds)
  const range = state.pending[index] as RangeBounds
  const pending = [...state.pending]
  if (response.bounds.upper === range.upper) {
    pending.splice(index, 1)
  } else {
    pending[index] = { type: range.type, lower: response.bounds.upper, upper: range.upper }
  }

  const steps = nextRequesterSteps(local, response)
  let requested = state.requested
  for (const step of steps) {
    if ('answer' in step) {
      if (step.answer === 'differs') {
        pending.push(step.bounds)
      }
      continue
    }
    // No id can already be in `requested`: pending ranges never overlap, a response is
    // accepted only inside one, and that part leaves `pending` as it is accepted. So the ids
    // of one pass's leaf lists are disjoint, and `nextRequesterSteps` dedupes within a list.
    requested = [...requested, ...step.get]
  }
  return { state: { pending, requested, complete: pending.length === 0 }, steps }
}
