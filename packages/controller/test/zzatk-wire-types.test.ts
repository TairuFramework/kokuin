import { describe, expect, test } from 'vitest'

import { createInception, createRevoke, didFromInception, type SignedEvent } from '../src/events.js'
import { foldLog, foldLogAsync } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const delegateSeed = new Uint8Array(32).fill(9)
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  const r = foldLog(did, [icp])
  if (!r.ok) throw new Error('fixture')
  return { icp, did, digest: r.states[0].digest }
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
    console.log(
      'event with no `crit` member:',
      r.ok ? 'SKIPPED (fold ok)' : `rejected — ${r.reason}`,
    )
    expect(r.ok).toBe(false)
  })

  test('ROW 2 (closed): only the boolean `false` is skipped; every other spelling fails closed', () => {
    const { icp, did, digest } = build()
    const skipped: Array<string> = []
    for (const crit of [false, 0, '', null, undefined, 'false', 'no', 1, {}, []]) {
      const event = { v: 1, t: 'nop', i: did, g: 0, s: 1, p: digest, crit }
      const r = foldLog(did, [icp, { event, sigs: [] } as unknown as SignedEvent])
      console.log(
        `crit=${JSON.stringify(crit)} ->`,
        r.ok ? 'SKIPPED' : `failed closed (${r.reason})`,
      )
      if (r.ok) skipped.push(JSON.stringify(crit))
    }
    // Every falsy spelling — `0`, `''`, `null`, an omitted member — used to reach the skip path
    // alongside the boolean. Only the boolean does now.
    expect(skipped).toEqual(['false'])
  })

  // CLOSED. `cap` is type-checked in `stepEvent` beside `x`, so caller-supplied verifier code is
  // never handed a `cap` that is not a string. Construction untouched; the assertion is inverted
  // and the control below — which already showed `x` being checked — now shows the two agreeing.
  test('ROW 3 (closed): `cap` is checked in `stepEvent`, like `x` right above it', async () => {
    const { icp, did } = build()
    const rev = createRevoke(delegateSeed, 0, did, icp.event, target, { gen: 0, seq: 0 })
    // One field mutated: `cap` set to a non-string. `x` is type-checked in `stepEvent`; `cap` is
    // not, and it crosses a `(cap: string, ...)` callback boundary.
    const forged = {
      ...rev,
      event: { ...rev.event, cap: { lifted: 'from another log' } },
    } as unknown as SignedEvent

    let seenType = 'never called'
    const result = await foldLogAsync(did, [icp, forged], {
      verifyCapability: async (cap) => {
        seenType = `${typeof cap}: ${JSON.stringify(cap)}`
        return { authorised: false, reason: 'declined' }
      },
    })
    console.log('verifier received cap as', seenType)
    console.log('fold answered:', result.ok ? 'ACCEPTED' : `rejected — ${result.reason}`)
    expect(seenType).toBe('never called')
    expect(result).toEqual({
      ok: false,
      reason: 'revoke capability is not a serialized token',
      index: 1,
    })

    // CONTROL: the same event with `x` — the field right beside it — set to a non-string is
    // rejected by the fold before the verifier is reached.
    const badX = {
      ...rev,
      event: { ...rev.event, x: { not: 'a string' } },
    } as unknown as SignedEvent
    let called = false
    const control = await foldLogAsync(did, [icp, badX], {
      verifyCapability: async () => {
        called = true
        return { authorised: false, reason: 'declined' }
      },
    })
    console.log('CONTROL non-string `x`:', control.ok ? 'ACCEPTED' : `rejected — ${control.reason}`)
    console.log('CONTROL verifier called:', called)
    expect(called).toBe(false)

    // Second control: the same event with a well-formed string `cap` does reach the verifier, so
    // the rejection above is the member's type and not the capability path having gone away.
    const wellFormed = {
      ...rev,
      event: { ...rev.event, cap: 'header.payload.signature' },
    } as unknown as SignedEvent
    let reached: unknown = 'never called'
    await foldLogAsync(did, [icp, wellFormed], {
      verifyCapability: async (cap) => {
        reached = cap
        return { authorised: false, reason: 'declined' }
      },
    })
    console.log('CONTROL string `cap` reached the verifier:', reached)
    expect(reached).toBe('header.payload.signature')
  })
})
