import type { ResolvedSigningKey } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import { createInception, createRevoke, didFromInception } from '../src/events.js'
import { foldLog, foldLogAsync } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const delegateSeed = new Uint8Array(32).fill(9)
const outsiderSeed = new Uint8Array(32).fill(10)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const cap = 'eyJ.fake.token'

/** The key `createRevoke(<seed>, …)` signs with — what an authorising capability's `aud` resolves to. */
function signingKeyFor(revokeSeed: Uint8Array): ResolvedSigningKey {
  return {
    alg: 'EdDSA',
    publicKey: deriveKeyPair(revokeSeed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
  }
}

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

/** A cap-bearing revoke signed by the delegate, chained onto the inception. */
function capRevoke(did: string, icp: ReturnType<typeof createInception>) {
  return createRevoke(delegateSeed, 0, did, icp.event, stolen, { gen: 0, seq: 0 }, { cap })
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
    const result = foldLog(did, [icp, capRevoke(did, icp)])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/capability/)
  })

  test('the async fold accepts one when the injected verifier approves', async () => {
    const { icp, did } = build()
    const result = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async (capability, subject, target) => {
        expect(subject).toBe(did)
        expect(target).toBe(stolen)
        return capability === cap ? signingKeyFor(delegateSeed) : null
      },
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(stolen)).toBe(true)
  })

  test('the async fold rejects one the verifier declines', async () => {
    const { icp, did } = build()
    const result = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async () => null,
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('capability does not authorise this revoke')
  })

  test('the async fold rejects one the authorised party did not sign', async () => {
    // The verifier approves — the capability really does grant this revoke — but to somebody
    // else. The event is the delegate's. Nothing the verifier sees could catch that, which is why
    // it hands back the audience's key instead of a yes.
    const { icp, did } = build()
    const result = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async () => signingKeyFor(outsiderSeed),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('revoke is not signed by the capability audience')
  })

  test('the async fold rejects a cap-bearing revoke carrying no signature at all', async () => {
    // Before the audience binding, `sigs` was never read on this path: an event with an empty
    // signature list and a lifted capability folded cleanly.
    const { icp, did } = build()
    const unsigned = { ...capRevoke(did, icp), sigs: [] }
    const result = await foldLogAsync(did, [icp, unsigned], {
      verifyCapability: async () => signingKeyFor(delegateSeed),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('revoke is not signed by the capability audience')
  })
})
