import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  signEvent,
  verifyReset,
  verifyRotate,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'

const seed = new Uint8Array(32).fill(1)

async function setup() {
  const inception = await createInception(seed, 0)
  return {
    inception,
    did: didFromInception(inception.event),
  }
}

describe('createReset()', () => {
  test('increments the generation and restarts the sequence', async () => {
    const { event } = await createReset({ seed: seed, profile: 0, gen: 1 })
    expect(event.g).toBe(1)
    expect(event.s).toBe(0)
  })

  test('is a rotate variant, not a fourth event type', async () => {
    expect((await createReset({ seed: seed, profile: 0, gen: 1 })).event.t).toBe('rot')
  })

  test('clears the deny set by carrying an empty snapshot', async () => {
    expect((await createReset({ seed: seed, profile: 0, gen: 1 })).event.d).toEqual([])
  })

  test('anchors to the inception, with no reference to any event beyond it', async () => {
    const { inception, did } = await setup()
    const { event } = await createReset({ seed: seed, profile: 0, gen: 1 })
    expect(event.p).toBe(digestOf(inception.event))
    expect(event.i).toBe(did)
  })

  test('is a pure function of (seed, profile, gen) — two blind resets are byte-identical', async () => {
    expect(await createReset({ seed: seed, profile: 0, gen: 1 })).toEqual(
      await createReset({ seed: seed, profile: 0, gen: 1 }),
    )
  })

  test('rejects a generation below 1', async () => {
    await expect(
      async () => await createReset({ seed: seed, profile: 0, gen: 0 }),
    ).rejects.toThrow()
  })
})

describe('verifyReset()', () => {
  test('accepts a reset signed by the committed recovery key', async () => {
    const { inception } = await setup()
    const signed = await createReset({ seed: seed, profile: 0, gen: 1 })
    expect(await verifyReset(signed, inception.event)).toBe(true)
  })

  test('rejects a reset signed by any other key — the root always wins the race', async () => {
    const { inception } = await setup()
    const thiefSeed = new Uint8Array(32).fill(9)
    const signed = await createReset({ seed: thiefSeed, profile: 0, gen: 1 })
    expect(await verifyReset(signed, inception.event)).toBe(false)
  })

  test('rejects a reset that does not increment the generation', async () => {
    const { inception } = await setup()
    const signed = await createReset({ seed: seed, profile: 0, gen: 1 })
    const tampered = { ...signed, event: { ...signed.event, g: 0 } }
    expect(await verifyReset(tampered, inception.event)).toBe(false)
  })

  // `p`/`s`/`g` and the revealed recovery key stay exactly as createReset produced them, and the
  // event is re-signed with the real recovery private key over the tampered bytes — so only a
  // dedicated `ka` check, not a chain/recovery/signature failure, can reject these.
  test('rejects a reset publishing no key agreement key', async () => {
    const { inception } = await setup()
    const signed = await createReset({ seed: seed, profile: 0, gen: 1 })
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, ka: [] }
    const sigs = await signEvent(event, [recovery.privateKey])
    expect(
      await verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event),
    ).toBe(false)
  })

  test('rejects a reset whose ka holds a key that is not X25519-tagged', async () => {
    const { inception } = await setup()
    const signed = await createReset({ seed: seed, profile: 0, gen: 1 })
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const signingKey = signed.event.k[0]
    if (signingKey === undefined) throw new Error('expected a signing key')
    const event = { ...signed.event, ka: [signingKey] }
    const sigs = await signEvent(event, [recovery.privateKey])
    expect(
      await verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event),
    ).toBe(false)
  })

  // A blind reset carries `d: []`, no `m` and no seal — that is what makes "blind reset" mean the
  // same bytes for every holder of the same seed, which the branch selector relies on to treat two
  // blind resets at one generation as idempotent rather than as a fork. A reset may instead carry a
  // whole snapshot, `m` and `d` together; half of one is refused. Each body below is re-signed by the
  // real recovery key, so only a dedicated check can reject it.
  test('rejects a reset carrying a deny set but no member list', async () => {
    const { inception } = await setup()
    const signed = await createReset({ seed: seed, profile: 0, gen: 1 })
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, d: ['did:key:zStillDenied'] }
    const sigs = await signEvent(event, [recovery.privateKey])
    expect(
      await verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event),
    ).toBe(false)
  })

  test('rejects a reset carrying a member list but no deny set', async () => {
    const { inception } = await setup()
    const signed = await createReset({
      seed: seed,
      profile: 0,
      gen: 1,
      snapshot: { members: [], deny: ['did:key:zStillDenied'] },
    })
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const { d: _d, ...event } = signed.event
    expect(event.m).toEqual([])
    const sigs = await signEvent(event, [recovery.privateKey])
    expect(
      await verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event),
    ).toBe(false)
  })

  test('accepts a reset carrying a whole snapshot', async () => {
    const { inception } = await setup()
    const signed = await createReset({
      seed: seed,
      profile: 0,
      gen: 1,
      snapshot: { members: [], deny: ['did:key:zStillDenied'] },
    })
    expect(signed.event.m).toEqual([])
    expect(signed.event.d).toEqual(['did:key:zStillDenied'])
    expect(await verifyReset(signed, inception.event)).toBe(true)
  })

  test('rejects a reset carrying a seal', async () => {
    const { inception } = await setup()
    const signed = await createReset({ seed: seed, profile: 0, gen: 1 })
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, a: digestOf('an anchored grant') }
    const sigs = await signEvent(event, [recovery.privateKey])
    expect(
      await verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event),
    ).toBe(false)
  })
})

describe('the recovery commitment is fixed at inception', () => {
  // `RotateEvent` used to carry an optional `r` documented as a recovery-commitment update. Nothing
  // verified it and nothing read it: `verifyReset` checks `inception.r` and only that, so the
  // original recovery key could never be retired while `KeyState.recovery` reported a replacement.
  // The field is gone, and the fold refuses an event that carries one rather than ignoring it —
  // a member the fold silently drops is the same lie in a different place.
  //
  // The alternative (a recovery co-signature on a rotate that moves `r`) was rejected: a reset
  // anchors to the inception precisely so a root holding nothing but its seed can author one with
  // no log knowledge or availability, and a movable commitment makes the root read the log first.
  const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

  test('a rotate carrying `r` is refused, at every position and by both verifiers', async () => {
    const { inception, did } = await setup()
    const rot = await createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const withRecovery = { ...rot.event, r: digestOf('anything at all') }
    const key = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
    const forged = { event: withRecovery, sigs: await signEvent(withRecovery, [key.privateKey]) }

    expect(
      await verifyRotate(forged, { digest: digestOf(inception.event), n: inception.event.n }),
    ).toBe(false)
    expect(await foldLog(did, { chain: [inception, forged], events: [] })).toEqual({
      ok: false,
      reason: 'invalid rotate',
      index: 1,
    })

    // Control: the identical body without `r`, signed by the same key. The rejection is the member.
    const plain = { ...rot.event }
    const control = { event: plain, sigs: await signEvent(plain, [key.privateKey]) }
    expect(
      await verifyRotate(control, { digest: digestOf(inception.event), n: inception.event.n }),
    ).toBe(true)
    expect((await foldLog(did, { chain: [inception, control], events: [] })).ok).toBe(true)
  })

  test('a reset carrying `r` is refused too — it is a rotate body and shares the check', async () => {
    const { inception, did } = await setup()
    const signed = await createReset({ seed: seed, profile: 0, gen: 1 })
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, r: digestOf('anything at all') }
    const sigs = await signEvent(event, [recovery.privateKey])

    expect(
      await verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event),
    ).toBe(false)
    // Control: the same reset without the member verifies and folds.
    expect(await verifyReset(signed, inception.event)).toBe(true)
    expect((await foldLog(did, { chain: [inception, signed], events: [] })).ok).toBe(true)
  })

  test('`KeyState.recovery` is the inception commitment at every position of a mixed log', async () => {
    // Including across a reset, which opens a new generation under the same root — and this is the
    // value `verifyReset` enforces, so the state and the verifier agree by construction now.
    const { inception, did } = await setup()
    const rot = await createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const denying = await createRotate({
      seed,
      profile: 0,
      did,
      prior: rot.event,
      snapshot: { members: [], deny: [target] },
    })
    const reset = await createReset({ seed: seed, profile: 0, gen: 1 })
    const after = await createRotate({
      seed,
      profile: 0,
      did,
      prior: reset.event,
      snapshot: { members: [], deny: [] },
    })

    const result = await foldLog(did, {
      chain: [inception, rot, denying, reset, after],
      events: [],
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states.map((state) => state.recovery)).toEqual(
      result.states.map(() => inception.event.r),
    )
    // And the value is the digest of the key `recoveryPath` derives, which is what a restored
    // mnemonic reproduces without the log.
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    expect(inception.event.r).toBe(digestOf(encodeKey(recovery.publicKey, 'EdDSA')))
  })
})
