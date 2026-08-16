import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  keyTarget,
} from '@kokuin/controller'
import { type MethodRegistry, randomIdentity, stringifyToken, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { checkCapability, createCapability, now } from '../src/index.js'

// Does the resolve/resolveHistoric split actually stop a rotated-away authority key from minting
// NEW authority? `@kokuin/capability` opts into historic resolution unconditionally, so this asks
// the question at the capability path rather than the plain-token path.
//
// A rotate alone cannot and must not stop the mint: `HISTORIC_ISSUANCE` in `src/index.ts` keeps an
// already-issued capability working across the subject's routine key hygiene, and a rotate that also
// invalidated archived material would break every outstanding grant — including the revocation
// records `revocation.ts` swallows a resolution failure on, the one path that must never fail open.
// So the escalation on a rotate-only log is asserted as the standing cost, and the second half of
// this file is the remedy it buys: an explicit `rev` naming the leaked KEY, after which the identical
// thief-minted capability is refused. The legitimacy row proves the refusal is the denial and not
// the extra event.

describe('a rotated-away authority key, at the capability path', () => {
  test('can it mint a fresh capability granting itself everything?', async () => {
    const seed = new Uint8Array(32).fill(31)
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate({ seed, profile: 0, did, prior: inception.event })
    const fullLog = [inception, rotate]

    // The verifier sees the WHOLE log: the profile has rotated, so the inception key is retired.
    const methods: MethodRegistry = [
      createControllerResolver({ loadLog: async (asked) => (asked === did ? fullLog : undefined) }),
    ]

    // The thief signs as the profile using only the PREFIX — i.e. with the rotated-away key,
    // naming it in `kid`. This is what holding a leaked, since-rotated authority key gives you.
    const stolen = createControllerIdentity({ seed, profile: 0, log: [inception] })
    const thiefDevice = await randomIdentity()

    const minted = await createCapability(stolen, {
      sub: did,
      aud: thiefDevice.id,
      act: '*',
      res: '*',
      exp: now() + 3600,
    })
    const raw = stringifyToken(minted)

    // Does a fresh capability minted by the retired key verify?
    let tokenVerified = true
    try {
      await verifyToken(raw, { methods })
    } catch {
      tokenVerified = false
    }

    // And does it grant authority through the capability path?
    let granted = true
    try {
      await checkCapability(
        { act: 'revoke', res: 'did:kokuin:zSomeoneElse' },
        { iss: thiefDevice.id, sub: did, cap: [raw] } as never,
        { methods },
      )
    } catch {
      granted = false
    }

    // Control for the row above: the identical token is refused by head-only resolution, so what
    // accepts it is the historic opt-in and nothing incidental.
    expect(tokenVerified).toBe(false)
    // The standing cost of `HISTORIC_ISSUANCE`, asserted so that a future change which quietly
    // removes it — and with it the survival of every already-issued capability across a rotate —
    // shows up here rather than in a consumer's outstanding grants.
    expect(granted).toBe(true)

    // ── The owner's remedy ────────────────────────────────────────────────────────────────────
    // One more event, signed by the authority key the rotate established: a `rev` whose target is
    // the leaked KEY rather than a device DID. Retirement is explicit precisely because rotation
    // is not allowed to be what retires.
    const leakedKey = inception.event.k[0]
    const revoke = createRevoke({
      seed,
      profile: 0,
      did,
      prior: rotate.event,
      target: keyTarget(leakedKey),
      keyPosition: {
        gen: 0,
        seq: 1,
      },
    })
    const remediedLog = [inception, rotate, revoke]
    const remedied: MethodRegistry = [
      createControllerResolver({
        loadLog: async (asked) => (asked === did ? remediedLog : undefined),
      }),
    ]

    // The SAME serialized capability — not a re-mint — against the log that now denies its key.
    let grantedAfterRevoke = true
    let refusal = ''
    try {
      await checkCapability(
        { act: 'revoke', res: 'did:kokuin:zSomeoneElse' },
        { iss: thiefDevice.id, sub: did, cap: [raw] } as never,
        { methods: remedied },
      )
    } catch (err) {
      grantedAfterRevoke = false
      refusal = (err as Error).message
    }

    // Legitimacy control: on the very same three-event log, a capability minted by the key the
    // profile currently holds still grants. Without this row a rejection above could just as well
    // be the third event making the log unfoldable, or historic resolution collapsing outright —
    // both of which would "pass" the assertion while denying every honest holder too.
    const owner = createControllerIdentity({ seed, profile: 0, log: remediedLog })
    const honestDevice = await randomIdentity()
    const honest = stringifyToken(
      await createCapability(owner, {
        sub: did,
        aud: honestDevice.id,
        act: '*',
        res: '*',
        exp: now() + 3600,
      }),
    )
    let honestGranted = true
    try {
      await checkCapability(
        { act: 'revoke', res: 'did:kokuin:zSomeoneElse' },
        { iss: honestDevice.id, sub: did, cap: [honest] } as never,
        { methods: remedied },
      )
    } catch {
      honestGranted = false
    }

    expect(honestGranted).toBe(true)
    expect(grantedAfterRevoke).toBe(false)
    // And refused *for the denial*, not for an incidental resolution or signature failure.
    expect(refusal).toContain('has revoked')
    expect(refusal).toContain(keyTarget(leakedKey))
  })
})
