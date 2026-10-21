import { describe, expect, test } from 'vitest'

import { createInception, createRevoke, didFromInception, type SignedEvent } from '../src/events.js'
import { foldLog } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const delegateSeed = new Uint8Array(32).fill(9)
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  const r = foldLog(did, [icp])
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
    const r = foldLog(did, [icp, noCrit])
    expect(r.ok).toBe(false)
  })

  test('ROW 2 (closed): only the boolean `false` is skipped; every other spelling fails closed', () => {
    const { icp, did, digest } = build()
    const skipped: Array<string> = []
    for (const crit of [false, 0, '', null, undefined, 'false', 'no', 1, {}, []]) {
      const event = { v: 1, t: 'nop', i: did, g: 0, s: 1, p: digest, crit }
      const r = foldLog(did, [icp, { event, sigs: [] } as unknown as SignedEvent])
      if (r.ok) skipped.push(JSON.stringify(crit))
    }
    // Every falsy spelling — `0`, `''`, `null`, an omitted member — used to reach the skip path
    // alongside the boolean. Only the boolean does now.
    expect(skipped).toEqual(['false'])
  })

  // CLOSED. A revoke has no `cap` member: whatever type one carries, the fold refuses it in
  // `stepEvent` rather than ignoring it, so an old capability-authorised revoke cannot be read as a
  // plain one.
  test('ROW 3 (closed): a `cap` of any type is refused, and `x` beside it is still checked', () => {
    const { icp, did } = build()
    const rev = createRevoke({
      seed: delegateSeed,
      profile: 0,
      did,
      prior: icp.event,
      target,
      keyPosition: { gen: 0, seq: 0 },
    })
    for (const cap of [{ lifted: 'from another log' }, 'header.payload.signature', null, 1]) {
      const forged = { ...rev, event: { ...rev.event, cap } } as unknown as SignedEvent
      expect(foldLog(did, [icp, forged])).toEqual({
        ok: false,
        reason: 'revoke capability is not supported',
        index: 1,
      })
    }

    // CONTROL: the same event with `x` — the field right beside it — set to a non-string is
    // rejected for its own reason, so the rejection above is the member and not the event.
    const badX = {
      ...rev,
      event: { ...rev.event, x: { not: 'a string' } },
    } as unknown as SignedEvent
    expect(foldLog(did, [icp, badX])).toEqual({
      ok: false,
      reason: 'revoke names no target',
      index: 1,
    })
  })
})
