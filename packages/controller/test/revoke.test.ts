import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRevoke,
  createRevokeWithKey,
  didFromInception,
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
    expect(createRevoke(seed, 0, did, inception.event, stolen, activeKey).event.x).toBe(stolen)
  })

  test('advances the sequence within the generation', () => {
    const { inception, did } = setup()
    const { event } = createRevoke(seed, 0, did, inception.event, stolen, activeKey)
    expect(event.s).toBe(1)
    expect(event.g).toBe(0)
  })

  test('is critical — a verifier that skips it accepts a revoked device', () => {
    const { inception, did } = setup()
    expect(createRevoke(seed, 0, did, inception.event, stolen, activeKey).event.crit).toBe(true)
  })

  test('does not rotate the key set', () => {
    const { inception, did } = setup()
    const { event } = createRevoke(seed, 0, did, inception.event, stolen, activeKey)
    expect(event).not.toHaveProperty('k')
    expect(event).not.toHaveProperty('n')
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

    expect(createRevokeWithKey(privateKey, did, inception.event, stolen)).toEqual(
      createRevoke(seed, 0, did, inception.event, stolen, activeKey),
    )
  })

  test('carries the capability the same way', () => {
    const { inception, did } = setup()
    const { privateKey } = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
    const signed = createRevokeWithKey(privateKey, did, inception.event, stolen, { cap: 'a-cap' })

    expect(signed.event.cap).toBe('a-cap')
    expect(signed.event.x).toBe(stolen)
  })

  test('signs with the key it was handed and nothing else', () => {
    // A device holding a management capability signs with its own key, which is not — and must not
    // have to be — one of the profile's authority keys.
    const { inception, did, priorDigest } = setup()
    const device = new Uint8Array(32).fill(77)
    const signed = createRevokeWithKey(device, did, inception.event, stolen)

    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })
})

describe('verifyRevoke()', () => {
  test('accepts a revoke signed by the current authority key', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRevoke(seed, 0, did, inception.event, stolen, activeKey)
    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(true)
  })

  test('rejects a revoke signed by an unrelated key', () => {
    const { inception, did, priorDigest } = setup()
    const thief = new Uint8Array(32).fill(9)
    const signed = createRevoke(thief, 0, did, inception.event, stolen, activeKey)
    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })

  test('rejects a tampered target — the DID is covered by the signature', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRevoke(seed, 0, did, inception.event, stolen, activeKey)
    const tampered = { ...signed, event: { ...signed.event, x: 'did:key:zOther' } }
    expect(verifyRevoke(tampered, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })

  test('a second revoke chained onto the first still signs at the active key position, not its own', () => {
    const { inception, did } = setup()
    const rev1 = createRevoke(seed, 0, did, inception.event, stolen, activeKey)
    const rev2 = createRevoke(
      seed,
      0,
      did,
      rev1.event,
      'did:key:z6MkAnotherStolenDeviceDidHere111111111111',
      // The active authority key is still the one established by the inception — a revoke
      // establishes no key of its own, so this stays { gen: 0, seq: 0 } rather than tracking
      // rev1's own position.
      activeKey,
    )
    expect(verifyRevoke(rev2, { digest: digestOf(rev1.event), keys: inception.event.k })).toBe(true)
  })
})
