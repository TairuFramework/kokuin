import { describe, expect, test } from 'vitest'

import { createInception, didFromInception } from '../src/events.js'
import { foldLog, foldLogAsync } from '../src/fold.js'

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
      p: (foldLog(did, [prior]) as { ok: true; states: Array<{ digest: string }> }).states[0]
        .digest,
      crit,
    },
    sigs: [],
  }
}

describe('criticality', () => {
  test('an unknown critical event fails the fold closed', () => {
    const { icp, did } = build()
    const result = foldLog(did, [icp, unknownEvent(did, icp, true)])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/unknown critical event/)
  })

  test('an unknown non-critical event is skipped and the fold continues', () => {
    const { icp, did } = build()
    const result = foldLog(did, [icp, unknownEvent(did, icp, false)])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    // Skipped events do not advance state, so the position maps to the last applied state.
    expect(result.states).toHaveLength(2)
    expect(result.states[1].seq).toBe(0)
  })

  test('a revoke is critical, so a verifier that cannot read it never accepts the device', () => {
    const { icp, did } = build()
    const forged = {
      event: { ...unknownEvent(did, icp, true).event, t: 'rev' as never, x: stolen },
      sigs: [],
    }
    expect(foldLog(did, [icp, forged]).ok).toBe(false)
  })
})

describe('capability-authorised revoke', () => {
  test('the sync fold rejects a cap-bearing revoke rather than trusting it', () => {
    const { icp, did } = build()
    const withCap = {
      event: {
        v: 1 as const,
        t: 'rev' as const,
        i: did,
        g: 0,
        s: 1,
        p: (foldLog(did, [icp]) as { ok: true; states: Array<{ digest: string }> }).states[0]
          .digest,
        crit: true,
        x: stolen,
        cap: 'eyJ.fake.token',
      },
      sigs: ['zzz'],
    }
    const result = foldLog(did, [icp, withCap])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/capability/)
  })

  test('the async fold accepts one when the injected verifier approves', async () => {
    const { icp, did } = build()
    const priorDigest = (foldLog(did, [icp]) as { ok: true; states: Array<{ digest: string }> })
      .states[0].digest
    const withCap = {
      event: {
        v: 1 as const,
        t: 'rev' as const,
        i: did,
        g: 0,
        s: 1,
        p: priorDigest,
        crit: true,
        x: stolen,
        cap: 'eyJ.fake.token',
      },
      sigs: ['zzz'],
    }
    const result = await foldLogAsync(did, [icp, withCap], {
      verifyCapability: async (cap, subject, target) => {
        expect(subject).toBe(did)
        expect(target).toBe(stolen)
        return cap === 'eyJ.fake.token'
      },
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(stolen)).toBe(true)
  })

  test('the async fold rejects one the verifier declines', async () => {
    const { icp, did } = build()
    const priorDigest = (foldLog(did, [icp]) as { ok: true; states: Array<{ digest: string }> })
      .states[0].digest
    const withCap = {
      event: {
        v: 1 as const,
        t: 'rev' as const,
        i: did,
        g: 0,
        s: 1,
        p: priorDigest,
        crit: true,
        x: stolen,
        cap: 'eyJ.fake.token',
      },
      sigs: ['zzz'],
    }
    const result = await foldLogAsync(did, [icp, withCap], {
      verifyCapability: async () => false,
    })
    expect(result.ok).toBe(false)
  })
})
