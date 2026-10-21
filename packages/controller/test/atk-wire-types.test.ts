import { describe, expect, test } from 'vitest'

import { createInception, didFromInception, type SignedEvent } from '../src/events.js'
import { foldLog } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  const r = foldLog(did, { chain: [icp], events: [] })
  if (!r.ok) throw new Error('fixture')
  const head = r.states[0]
  if (head === undefined) throw new Error('fixture')
  return { icp, did, digest: head.digest }
}

describe('wire types the fold never checks', () => {
  test('ROW 1 (closed): `crit` absent no longer reads as false, so the event fails closed', () => {
    // Was: an omitted `crit` is `undefined`, `undefined` is falsy, and the fold skipped the event
    // — an unknown type could opt out of criticality by saying nothing. Only an explicit
    // `crit: false` claims the skip path now. The construction is untouched; the assertion is not.
    const { icp, did, digest } = build()
    const noCrit = {
      event: { v: 1, t: 'nop', i: did, g: 0, s: 1, p: digest },
      sigs: [],
    } as unknown as SignedEvent
    const r = foldLog(did, { chain: [icp, noCrit], events: [] })
    expect(r.ok).toBe(false)
  })

  test('ROW 2 (closed): only the boolean `false` is skipped; every other spelling fails closed', () => {
    const { icp, did, digest } = build()
    const skipped: Array<string> = []
    for (const crit of [false, 0, '', null, undefined, 'false', 'no', 1, {}, []]) {
      const event = { v: 1, t: 'nop', i: did, g: 0, s: 1, p: digest, crit }
      const r = foldLog(did, {
        chain: [icp, { event, sigs: [] } as unknown as SignedEvent],
        events: [],
      })
      if (r.ok) skipped.push(JSON.stringify(crit))
    }
    // Every falsy spelling — `0`, `''`, `null`, an omitted member — used to reach the skip path
    // alongside the boolean. Only the boolean does now.
    expect(skipped).toEqual(['false'])
  })

  // CLOSED. The root chain carries no `rev`: a revoke from an older log, plain or
  // capability-authorised, reaches the unknown-type path and, being critical, fails the fold closed
  // rather than being read as anything — and a `cap` beside it changes nothing.
  test('ROW 3 (closed): a chain `rev`, with or without a `cap`, is an unknown critical event', () => {
    const { icp, did, digest } = build()
    const rev = { v: 1, t: 'rev', i: did, g: 0, s: 1, p: digest, crit: true, x: target }
    for (const event of [rev, { ...rev, cap: 'header.payload.signature' }]) {
      expect(
        foldLog(did, {
          chain: [icp, { event, sigs: ['AAAA'] } as unknown as SignedEvent],
          events: [],
        }),
      ).toEqual({
        ok: false,
        reason: 'unknown critical event type: rev',
        index: 1,
      })
    }
  })
})
