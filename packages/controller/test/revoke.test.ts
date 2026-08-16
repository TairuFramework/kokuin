import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRevoke,
  createRevokeWithKey,
  didFromInception,
  KEY_TARGET_PREFIX,
  keyFromTarget,
  keyTarget,
  verifyRevoke,
} from '../src/events.js'

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
// The inception establishes the active authority key at its own position, gen 0 / seq 0.
const activeKey = { gen: 0, seq: 0 }

function setup() {
  const inception = createInception(seed, 0)
  return {
    inception,
    did: didFromInception(inception.event),
    priorDigest: digestOf(inception.event),
  }
}

describe('createRevoke()', () => {
  test('names the device DID, not a capability jti', () => {
    const { inception, did } = setup()
    expect(
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        target: stolen,
        keyPosition: activeKey,
      }).event.x,
    ).toBe(stolen)
  })

  test('advances the sequence within the generation', () => {
    const { inception, did } = setup()
    const { event } = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target: stolen,
      keyPosition: activeKey,
    })
    expect(event.s).toBe(1)
    expect(event.g).toBe(0)
  })

  test('is critical — a verifier that skips it accepts a revoked device', () => {
    const { inception, did } = setup()
    expect(
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        target: stolen,
        keyPosition: activeKey,
      }).event.crit,
    ).toBe(true)
  })

  test('does not rotate the key set', () => {
    const { inception, did } = setup()
    const { event } = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target: stolen,
      keyPosition: activeKey,
    })
    expect(event).not.toHaveProperty('k')
    expect(event).not.toHaveProperty('n')
  })
})

describe('a key target', () => {
  // The spelling is a wire format and the whole of the ambiguity argument rests on it, so it is
  // asserted rather than left to the two call sites that build and read it.
  test('is spelled exactly the way a kid names a key', () => {
    const key = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    expect(keyTarget(key)).toBe(`#${key}`)
    expect(KEY_TARGET_PREFIX).toBe('#')
  })

  test('round-trips, and reads a DID target back as no key at all', () => {
    const key = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    expect(keyFromTarget(keyTarget(key))).toBe(key)
    // The disambiguation that lets one field and one deny set carry both forms: a DID can never
    // read as a key target, so a `did:` entry is never mistaken for a denied key and vice versa.
    expect(keyFromTarget(stolen)).toBeNull()
    expect(keyFromTarget('')).toBeNull()
  })

  test('rides in `x` like a DID does, and is covered by the signature', () => {
    const { inception, did, priorDigest } = setup()
    const target = keyTarget(inception.event.k[0])
    const signed = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target,
      keyPosition: activeKey,
    })
    expect(signed.event.x).toBe(target)
    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(true)

    const tampered = { ...signed, event: { ...signed.event, x: keyTarget('z6MkSomethingElse') } }
    expect(verifyRevoke(tampered, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })
})

describe('createRevokeWithKey()', () => {
  test('produces the identical event to the seed-taking form for the same key', () => {
    // The two builders must not drift: a capability holder's revoke and an authority's revoke are
    // the same wire object, differing only in where the signing key came from. Comparing the whole
    // signed event covers the canonical bytes, the base64url convention and the claim set at once.
    const { inception, did } = setup()
    const { privateKey } = deriveKeyPair(
      seed,
      authorityPath(0, activeKey.gen, activeKey.seq),
      'EdDSA',
    )

    expect(
      createRevokeWithKey({ privateKey, did, prior: inception.event, target: stolen }),
    ).toEqual(
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        target: stolen,
        keyPosition: activeKey,
      }),
    )
  })

  test('carries the capability the same way', () => {
    const { inception, did } = setup()
    const { privateKey } = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
    const signed = createRevokeWithKey({
      privateKey,
      did,
      prior: inception.event,
      target: stolen,
      cap: 'a-cap',
    })

    expect(signed.event.cap).toBe('a-cap')
    expect(signed.event.x).toBe(stolen)
  })

  test('signs with the key it was handed and nothing else', () => {
    // A device holding a management capability signs with its own key, which is not — and must not
    // have to be — one of the profile's authority keys.
    const { inception, did, priorDigest } = setup()
    const device = new Uint8Array(32).fill(77)
    const signed = createRevokeWithKey({
      privateKey: device,
      did,
      prior: inception.event,
      target: stolen,
    })

    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })
})

describe('verifyRevoke()', () => {
  test('accepts a revoke signed by the current authority key', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target: stolen,
      keyPosition: activeKey,
    })
    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(true)
  })

  test('rejects a revoke signed by an unrelated key', () => {
    const { inception, did, priorDigest } = setup()
    const thief = new Uint8Array(32).fill(9)
    const signed = createRevoke({
      seed: thief,
      profile: 0,
      did,
      prior: inception.event,
      target: stolen,
      keyPosition: activeKey,
    })
    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })

  test('rejects a tampered target — the DID is covered by the signature', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target: stolen,
      keyPosition: activeKey,
    })
    const tampered = { ...signed, event: { ...signed.event, x: 'did:key:zOther' } }
    expect(verifyRevoke(tampered, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })

  test('a second revoke chained onto the first still signs at the active key position, not its own', () => {
    const { inception, did } = setup()
    const rev1 = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target: stolen,
      keyPosition: activeKey,
    })
    const rev2 = createRevoke({
      seed,
      profile: 0,
      did,
      prior: rev1.event,
      target: 'did:key:z6MkAnotherStolenDeviceDidHere111111111111',
      keyPosition: activeKey,
    })
    expect(verifyRevoke(rev2, { digest: digestOf(rev1.event), keys: inception.event.k })).toBe(true)
  })
})
