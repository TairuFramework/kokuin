import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  signEvent,
  verifyReset,
  verifyRotate,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'

const seed = new Uint8Array(32).fill(1)

function setup() {
  const inception = createInception(seed, 0)
  return {
    inception,
    did: didFromInception(inception.event),
  }
}

describe('createReset()', () => {
  test('increments the generation and restarts the sequence', () => {
    const { event } = createReset(seed, 0, 1)
    expect(event.g).toBe(1)
    expect(event.s).toBe(0)
  })

  test('is a rotate variant, not a fourth event type', () => {
    expect(createReset(seed, 0, 1).event.t).toBe('rot')
  })

  test('clears the deny set by carrying an empty snapshot', () => {
    expect(createReset(seed, 0, 1).event.d).toEqual([])
  })

  test('anchors to the inception, with no reference to any event beyond it', () => {
    const { inception, did } = setup()
    const { event } = createReset(seed, 0, 1)
    expect(event.p).toBe(digestOf(inception.event))
    expect(event.i).toBe(did)
  })

  test('is a pure function of (seed, profile, gen) — two blind resets are byte-identical', () => {
    expect(createReset(seed, 0, 1)).toEqual(createReset(seed, 0, 1))
  })

  test('rejects a generation below 1', () => {
    expect(() => createReset(seed, 0, 0)).toThrow()
  })
})

describe('verifyReset()', () => {
  test('accepts a reset signed by the committed recovery key', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    expect(verifyReset(signed, inception.event)).toBe(true)
  })

  test('rejects a reset signed by any other key — the root always wins the race', () => {
    const { inception } = setup()
    const thiefSeed = new Uint8Array(32).fill(9)
    const signed = createReset(thiefSeed, 0, 1)
    expect(verifyReset(signed, inception.event)).toBe(false)
  })

  test('rejects a reset that does not increment the generation', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    const tampered = { ...signed, event: { ...signed.event, g: 0 } }
    expect(verifyReset(tampered, inception.event)).toBe(false)
  })

  // `p`/`s`/`g` and the revealed recovery key stay exactly as createReset produced them, and the
  // event is re-signed with the real recovery private key over the tampered bytes — so only a
  // dedicated `ka` check, not a chain/recovery/signature failure, can reject these.
  test('rejects a reset publishing no key agreement key', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, ka: [] }
    const sigs = signEvent(event, [recovery.privateKey])
    expect(verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event)).toBe(
      false,
    )
  })

  test('rejects a reset whose ka holds a key that is not X25519-tagged', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const signingKey = signed.event.k[0]
    if (signingKey === undefined) throw new Error('expected a signing key')
    const event = { ...signed.event, ka: [signingKey] }
    const sigs = signEvent(event, [recovery.privateKey])
    expect(verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event)).toBe(
      false,
    )
  })

  // A reset carries an empty deny set and no seal — that is what makes "blind reset" mean the same
  // bytes for every holder of the same seed, which the branch selector relies on to treat two blind
  // resets at one generation as idempotent rather than as a fork. The rule lives in `createReset`,
  // which always emits `d: []` and no `a`; the checker enforces it too, so a reset carrying either —
  // re-signed by the real recovery key, so only a dedicated check can reject it — does not fold as a
  // reset that clears-then-repopulates the deny set or anchors where a reset never should.
  test('rejects a reset carrying a non-empty deny snapshot', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, d: ['did:key:zStillDenied'] }
    const sigs = signEvent(event, [recovery.privateKey])
    expect(verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event)).toBe(
      false,
    )
  })

  test('rejects a reset carrying a seal', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, a: digestOf('an anchored grant') }
    const sigs = signEvent(event, [recovery.privateKey])
    expect(verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event)).toBe(
      false,
    )
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

  test('a rotate carrying `r` is refused, at every position and by both verifiers', () => {
    const { inception, did } = setup()
    const rot = createRotate({ seed, profile: 0, did, prior: inception.event })
    const withRecovery = { ...rot.event, r: digestOf('anything at all') }
    const key = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
    const forged = { event: withRecovery, sigs: signEvent(withRecovery, [key.privateKey]) }

    expect(verifyRotate(forged, { digest: digestOf(inception.event), n: inception.event.n })).toBe(
      false,
    )
    expect(foldLog(did, [inception, forged])).toEqual({
      ok: false,
      reason: 'invalid rotate',
      index: 1,
    })

    // Control: the identical body without `r`, signed by the same key. The rejection is the member.
    const plain = { ...rot.event }
    const control = { event: plain, sigs: signEvent(plain, [key.privateKey]) }
    expect(verifyRotate(control, { digest: digestOf(inception.event), n: inception.event.n })).toBe(
      true,
    )
    expect(foldLog(did, [inception, control]).ok).toBe(true)
  })

  test('a reset carrying `r` is refused too — it is a rotate body and shares the check', () => {
    const { inception, did } = setup()
    const signed = createReset(seed, 0, 1)
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, r: digestOf('anything at all') }
    const sigs = signEvent(event, [recovery.privateKey])

    expect(verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event)).toBe(
      false,
    )
    // Control: the same reset without the member verifies and folds.
    expect(verifyReset(signed, inception.event)).toBe(true)
    expect(foldLog(did, [inception, signed]).ok).toBe(true)
  })

  test('`KeyState.recovery` is the inception commitment at every position of a mixed log', () => {
    // Including across a reset, which opens a new generation under the same root — and this is the
    // value `verifyReset` enforces, so the state and the verifier agree by construction now.
    const { inception, did } = setup()
    const rot = createRotate({ seed, profile: 0, did, prior: inception.event })
    const rev = createRevoke({
      seed,
      profile: 0,
      did,
      prior: rot.event,
      target,
      keyPosition: { gen: 0, seq: 1 },
    })
    const reset = createReset(seed, 0, 1)
    const after = createRotate({ seed, profile: 0, did, prior: reset.event })

    const result = foldLog(did, [inception, rot, rev, reset, after])
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
