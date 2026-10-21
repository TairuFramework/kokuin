import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { createRevoke, type EpochEvent } from '../src/epoch-events.js'
import { createInception, didFromInception, keyTarget, type SignedEvent } from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { MAX_EPOCH_EVENTS, MAX_EVENT_PARENTS, MAX_LOG_EVENTS } from '../src/limits.js'
import { type ControllerLog, epochHeads, LOG_TOO_LARGE, mergeLogs, pruneLog } from '../src/log.js'

const seed = new Uint8Array(32).fill(1)
const profile = 0
const inception = createInception(seed, profile)
const did = didFromInception(inception.event)

const folded = foldLog(did, { chain: [inception], events: [] })
if (!folded.ok) {
  throw new Error(`fixture chain does not fold: ${folded.reason}`)
}
const head = folded.head

function revoke(parents: Array<string>, target: string): SignedEvent<EpochEvent> {
  return createRevoke({ signer: { root: { seed, profile } }, did, head, parents, target })
}

function logOf(events: Array<SignedEvent<EpochEvent>>): ControllerLog {
  return { chain: [inception], events }
}

describe('epochHeads', () => {
  test('an epoch with no applied events has the epoch itself as its one head', () => {
    expect(epochHeads(did, logOf([]))).toEqual([head.epoch])
  })

  test('a linear chain has its last event as the head', () => {
    const first = revoke([head.epoch], 'did:example:one')
    const second = revoke([digestOf(first.event)], 'did:example:two')
    const third = revoke([digestOf(second.event)], 'did:example:three')
    expect(epochHeads(did, logOf([first, second, third]))).toEqual([digestOf(third.event)])
  })

  test('concurrent events are all heads, sorted ascending', () => {
    const one = revoke([head.epoch], 'did:example:one')
    const two = revoke([head.epoch], 'did:example:two')
    const heads = epochHeads(did, logOf([one, two]))
    expect(heads).toEqual([digestOf(one.event), digestOf(two.event)].sort())
    expect(epochHeads(did, logOf([two, one]))).toEqual(heads)
  })

  test('an event that names every head applies and becomes the sole head', () => {
    const one = revoke([head.epoch], 'did:example:one')
    const two = revoke([head.epoch], 'did:example:two')
    const parents = epochHeads(did, logOf([one, two]))
    const merge = revoke(parents, 'did:example:three')
    const log = logOf([one, two, merge])
    const result = foldLog(did, log)
    expect(result.ok && result.applied).toContain(digestOf(merge.event))
    expect(epochHeads(did, log)).toEqual([digestOf(merge.event)])
  })

  test('a pending or rejected event is never a head', () => {
    const applied = revoke([head.epoch], 'did:example:one')
    const pending = revoke([digestOf('an event nobody holds')], 'did:example:two')
    // The head publishes this key, so the fold refuses to deny it.
    const rejected = revoke([head.epoch], keyTarget(head.keys[0] as string))
    const log = logOf([applied, pending, rejected])
    const result = foldLog(did, log)
    expect(result.ok && [result.pending, result.rejected]).toEqual([1, 1])
    expect(epochHeads(did, log)).toEqual([digestOf(applied.event)])
  })

  test('more tips than a builder may name give the smallest MAX_EVENT_PARENTS, which build', () => {
    const events = Array.from({ length: MAX_EVENT_PARENTS + 3 }, (_, i) =>
      revoke([head.epoch], `did:example:${i}`),
    )
    const tips = events.map((event) => digestOf(event.event)).sort()
    const heads = epochHeads(did, logOf(events))
    expect(heads).toEqual(tips.slice(0, MAX_EVENT_PARENTS))
    // The documented use, `parents: epochHeads(did, log)`, builds and applies.
    const merge = revoke(heads, 'did:example:merge')
    const after = foldLog(did, logOf([...events, merge]))
    expect(after.ok && after.applied).toContain(digestOf(merge.event))
    // The tips it left out are still tips, beside it, so the next event folds them in.
    const next = epochHeads(did, logOf([...events, merge]))
    expect(next).toEqual([...tips.slice(MAX_EVENT_PARENTS), digestOf(merge.event)].sort())
    const last = revoke(next, 'did:example:last')
    expect(epochHeads(did, logOf([...events, merge, last]))).toEqual([digestOf(last.event)])
  })

  test('a log larger than any a verifier holds is refused before folding', () => {
    const events = Array.from(
      { length: MAX_LOG_EVENTS + MAX_EPOCH_EVENTS + 2 },
      () => null,
    ) as unknown as Array<SignedEvent<EpochEvent>>
    expect(() => epochHeads(did, logOf(events))).toThrow(LOG_TOO_LARGE)
    expect(() => pruneLog(did, logOf(events))).toThrow(LOG_TOO_LARGE)
    expect(() => mergeLogs(did, logOf(events), logOf([]))).toThrow(LOG_TOO_LARGE)
    expect(() => mergeLogs(did, logOf([]), logOf(events))).toThrow(LOG_TOO_LARGE)
    // One short of the limit is only junk: dropped, never refused.
    const within = events.slice(1)
    expect(epochHeads(did, logOf(within))).toEqual([head.epoch])
    expect(pruneLog(did, logOf(within)).events).toEqual([])
    expect(mergeLogs(did, logOf(within), logOf([])).events).toEqual([])
  })

  test('a log that does not fold throws with the fold reason', () => {
    const broken: ControllerLog = { chain: [], events: [] }
    const result = foldLog(did, broken)
    expect(result.ok).toBe(false)
    expect(() => epochHeads(did, broken)).toThrow(result.ok ? '' : result.reason)
  })
})
