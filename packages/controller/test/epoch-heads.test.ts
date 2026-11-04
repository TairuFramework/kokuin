import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { createRevoke, type EpochEvent } from '../src/epoch-events.js'
import { createInception, didFromInception, keyTarget, type SignedEvent } from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { MAX_EPOCH_EVENTS, MAX_EVENT_PARENTS, MAX_LOG_EVENTS } from '../src/limits.js'
import { type ControllerLog, epochHeads, LOG_TOO_LARGE, mergeLogs, pruneLog } from '../src/log.js'

const seed = new Uint8Array(32).fill(1)
const profile = 0
const inception = await createInception(seed, profile)
const did = didFromInception(inception.event)

const folded = await foldLog(did, { chain: [inception], events: [] })
if (!folded.ok) {
  throw new Error(`fixture chain does not fold: ${folded.reason}`)
}
const head = folded.head

async function revoke(parents: Array<string>, target: string): Promise<SignedEvent<EpochEvent>> {
  return await createRevoke({ signer: { root: { seed, profile } }, did, head, parents, target })
}

function logOf(events: Array<SignedEvent<EpochEvent>>): ControllerLog {
  return { chain: [inception], events }
}

describe('epochHeads', () => {
  test('an epoch with no applied events has the epoch itself as its one head', async () => {
    expect(await epochHeads(did, logOf([]))).toEqual([head.epoch])
  })

  test('a linear chain has its last event as the head', async () => {
    const first = await revoke([head.epoch], 'did:example:one')
    const second = await revoke([digestOf(first.event)], 'did:example:two')
    const third = await revoke([digestOf(second.event)], 'did:example:three')
    expect(await epochHeads(did, logOf([first, second, third]))).toEqual([digestOf(third.event)])
  })

  test('concurrent events are all heads, sorted ascending', async () => {
    const one = await revoke([head.epoch], 'did:example:one')
    const two = await revoke([head.epoch], 'did:example:two')
    const heads = await epochHeads(did, logOf([one, two]))
    expect(heads).toEqual([digestOf(one.event), digestOf(two.event)].sort())
    expect(await epochHeads(did, logOf([two, one]))).toEqual(heads)
  })

  test('an event that names every head applies and becomes the sole head', async () => {
    const one = await revoke([head.epoch], 'did:example:one')
    const two = await revoke([head.epoch], 'did:example:two')
    const parents = await epochHeads(did, logOf([one, two]))
    const merge = await revoke(parents, 'did:example:three')
    const log = logOf([one, two, merge])
    const result = await foldLog(did, log)
    expect(result.ok && result.applied).toContain(digestOf(merge.event))
    expect(await epochHeads(did, log)).toEqual([digestOf(merge.event)])
  })

  test('a pending or rejected event is never a head', async () => {
    const applied = await revoke([head.epoch], 'did:example:one')
    const pending = await revoke([digestOf('an event nobody holds')], 'did:example:two')
    // The head publishes this key, so the fold refuses to deny it.
    const rejected = await revoke([head.epoch], keyTarget(head.keys[0] as string))
    const log = logOf([applied, pending, rejected])
    const result = await foldLog(did, log)
    expect(result.ok && [result.pending, result.rejected]).toEqual([1, 1])
    expect(await epochHeads(did, log)).toEqual([digestOf(applied.event)])
  })

  test('more tips than a builder may name give the smallest MAX_EVENT_PARENTS, which build', async () => {
    const events = await Promise.all(
      Array.from(
        { length: MAX_EVENT_PARENTS + 3 },
        async (_, i) => await revoke([head.epoch], `did:example:${i}`),
      ),
    )
    const tips = events.map((event) => digestOf(event.event)).sort()
    const heads = await epochHeads(did, logOf(events))
    expect(heads).toEqual(tips.slice(0, MAX_EVENT_PARENTS))
    // The documented use, `parents: epochHeads(did, log)`, builds and applies.
    const merge = await revoke(heads, 'did:example:merge')
    const after = await foldLog(did, logOf([...events, merge]))
    expect(after.ok && after.applied).toContain(digestOf(merge.event))
    // The tips it left out are still tips, beside it, so the next event folds them in.
    const next = await epochHeads(did, logOf([...events, merge]))
    expect(next).toEqual([...tips.slice(MAX_EVENT_PARENTS), digestOf(merge.event)].sort())
    const last = await revoke(next, 'did:example:last')
    expect(await epochHeads(did, logOf([...events, merge, last]))).toEqual([digestOf(last.event)])
  })

  test('a log larger than any a verifier holds is refused before folding', async () => {
    const events = Array.from(
      { length: MAX_LOG_EVENTS + MAX_EPOCH_EVENTS + 2 },
      () => null,
    ) as unknown as Array<SignedEvent<EpochEvent>>
    await expect(async () => await epochHeads(did, logOf(events))).rejects.toThrow(LOG_TOO_LARGE)
    await expect(async () => await pruneLog(did, logOf(events))).rejects.toThrow(LOG_TOO_LARGE)
    await expect(
      async () => await mergeLogs({ did: did, left: logOf(events), right: logOf([]) }),
    ).rejects.toThrow(LOG_TOO_LARGE)
    await expect(
      async () => await mergeLogs({ did: did, left: logOf([]), right: logOf(events) }),
    ).rejects.toThrow(LOG_TOO_LARGE)
    // One short of the limit is only junk: dropped, never refused.
    const within = events.slice(1)
    expect(await epochHeads(did, logOf(within))).toEqual([head.epoch])
    expect((await pruneLog(did, logOf(within))).events).toEqual([])
    expect((await mergeLogs({ did: did, left: logOf(within), right: logOf([]) })).events).toEqual(
      [],
    )
  })

  test('a log that does not fold throws with the fold reason', async () => {
    const broken: ControllerLog = { chain: [], events: [] }
    const result = await foldLog(did, broken)
    expect(result.ok).toBe(false)
    await expect(async () => await epochHeads(did, broken)).rejects.toThrow(
      result.ok ? '' : result.reason,
    )
  })
})
