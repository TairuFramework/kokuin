import { describe, expect, test } from 'vitest'

import { createInception, didFromInception } from '../src/events.js'
import { foldLog } from '../src/fold.js'

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

function unknownEvent(did: string, prior: ReturnType<typeof createInception>, crit: boolean) {
  return {
    event: {
      v: 1 as const,
      t: 'xyz' as never,
      i: did,
      g: 0,
      s: 1,
      p: at(
        (
          foldLog(did, { chain: [prior], events: [] }) as {
            ok: true
            states: Array<{ digest: string }>
          }
        ).states,
        0,
      ).digest,
      crit,
    },
    sigs: [],
  }
}

describe('criticality', () => {
  test('an unknown critical event fails the fold closed', () => {
    const { icp, did } = build()
    const result = foldLog(did, { chain: [icp, unknownEvent(did, icp, true)], events: [] })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/unknown critical event/)
  })

  test('an unknown non-critical event is skipped and the fold continues', () => {
    const { icp, did } = build()
    const result = foldLog(did, { chain: [icp, unknownEvent(did, icp, false)], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    // Skipped events do not advance state, so the position maps to the last applied state.
    expect(result.states).toHaveLength(2)
    expect(at(result.states, 1).seq).toBe(0)
  })

  test('an unknown event with no `crit` member fails closed rather than skipping', () => {
    // `crit` is wire data, and an absent member reads as `undefined`. Under a truthiness test that
    // was the skip path, so an unknown type could opt out of criticality by saying nothing at all.
    const { icp, did } = build()
    const { event } = unknownEvent(did, icp, false)
    const { crit: _crit, ...withoutCrit } = event
    const result = foldLog(did, {
      chain: [icp, { event: withoutCrit as typeof event, sigs: [] }],
      events: [],
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/no criticality flag/)
  })

  test('a skipped event may only claim the next sequence position', () => {
    // The one event the fold accepts without checking a signature — it cannot, not knowing the
    // type's rules — so its position must not be free wire data. `resolveBranches` orders branches
    // by position, and a fabricated one is a branch nothing the controller authors can outrank.
    const { icp, did } = build()
    const skipped = unknownEvent(did, icp, false)
    const positions: Array<[number, number]> = [
      [0, Number.MAX_SAFE_INTEGER],
      [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
      [1, 1],
      [0, 0],
      [0, 2],
    ]
    for (const [g, s] of positions) {
      const result = foldLog(did, {
        chain: [icp, { ...skipped, event: { ...skipped.event, g, s } }],
        events: [],
      })
      expect(result).toEqual({ ok: false, reason: 'sequence gap', index: 1 })
    }
    // The truthful position still folds.
    expect(foldLog(did, { chain: [icp, skipped], events: [] }).ok).toBe(true)
  })

  test('a revoke is critical, so a verifier that cannot read it never accepts the device', () => {
    const { icp, did } = build()
    const forged = {
      event: { ...unknownEvent(did, icp, true).event, t: 'rev' as never, x: stolen },
      sigs: [],
    }
    expect(foldLog(did, { chain: [icp, forged], events: [] }).ok).toBe(false)
  })
})
