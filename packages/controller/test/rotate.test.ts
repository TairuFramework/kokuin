import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRotate,
  didFromInception,
  encodeKey,
  signEvent,
  verifyRotate,
  verifySignatures,
} from '../src/events.js'

const seed = new Uint8Array(32).fill(1)

function setup() {
  const inception = createInception(seed, 0)
  const did = didFromInception(inception.event)
  return { inception, did, priorDigest: digestOf(inception.event) }
}

describe('createRotate()', () => {
  test('advances the sequence and keeps the generation', () => {
    const { inception, did } = setup()
    const { event } = createRotate(seed, 0, did, inception.event)
    expect(event.s).toBe(1)
    expect(event.g).toBe(0)
  })

  test('names the DID explicitly, unlike inception', () => {
    const { inception, did } = setup()
    expect(createRotate(seed, 0, did, inception.event).event.i).toBe(did)
  })

  test('chains to the previous event by digest', () => {
    const { inception, did, priorDigest } = setup()
    expect(createRotate(seed, 0, did, inception.event).event.p).toBe(priorDigest)
  })

  test('reveals the keys the prior event pre-committed', () => {
    const { inception, did } = setup()
    const { event } = createRotate(seed, 0, did, inception.event)
    expect(digestOf(event.k[0])).toBe(inception.event.n[0])
  })

  test('is reproducible from the seed when it carries no optional fields', () => {
    const { inception, did } = setup()
    expect(createRotate(seed, 0, did, inception.event)).toEqual(
      createRotate(seed, 0, did, inception.event),
    )
  })

  test('carries a seal when one is given', () => {
    const { inception, did } = setup()
    const seal = digestOf({ grant: 'management' })
    expect(createRotate(seed, 0, did, inception.event, { seal }).event.a).toBe(seal)
  })

  test('carries a deny-set snapshot when one is given', () => {
    const { inception, did } = setup()
    const deny = ['did:key:zStolen']
    expect(createRotate(seed, 0, did, inception.event, { deny }).event.d).toEqual(deny)
  })
})

describe('verifyRotate()', () => {
  test('accepts a rotate signed by the pre-committed next keys', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    expect(verifyRotate(signed, { digest: priorDigest, n: inception.event.n })).toBe(true)
  })

  test('rejects a rotate whose keys were not pre-committed — a stolen device cannot rotate', () => {
    const { inception, did, priorDigest } = setup()
    const other = new Uint8Array(32).fill(9)
    const signed = createRotate(other, 0, did, inception.event)
    expect(verifyRotate(signed, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })

  test('rejects a rotate that does not chain to the prior digest', () => {
    const { inception, did } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    expect(verifyRotate(signed, { digest: digestOf({ other: true }), n: inception.event.n })).toBe(
      false,
    )
  })

  test('rejects a tampered deny snapshot — it is covered by the signature', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    const tampered = { ...signed, event: { ...signed.event, d: ['did:key:zInjected'] } }
    expect(verifyRotate(tampered, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })

  test('rejects a key presented as an authority key when it is X25519-tagged, not EdDSA', () => {
    // A caller must not be able to present a key agreement key as an authority key by swapping
    // the tag a verifier trusts without checking. Mistagging the real authority key (rather than
    // substituting a different one, or reusing the original signature) and re-signing with its
    // real private key gives a genuinely valid Ed25519 signature over these exact bytes — so this
    // only fails if verification checks the tag, not just whether the signature verifies.
    const { inception, did } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    const current = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
    const event = { ...signed.event, k: [encodeKey(current.publicKey, 'X25519')] }
    const sigs = signEvent(event, [current.privateKey])
    expect(verifySignatures(event, sigs, event.k)).toBe(false)
  })

  // `k` and `p` stay exactly as createRotate produced them, so the pre-rotation and chaining
  // checks pass; re-signing with the real revealed key over the tampered bytes gives a genuinely
  // valid signature, so only a dedicated `ka` check — not a signature failure — can reject these.
  test('rejects a rotate publishing no key agreement key', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    const current = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
    const event = { ...signed.event, ka: [] }
    const sigs = signEvent(event, [current.privateKey])
    expect(verifyRotate({ event, sigs }, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })

  test('rejects a rotate whose ka holds a key that is not X25519-tagged', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    const current = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
    const event = { ...signed.event, ka: [signed.event.k[0]] }
    const sigs = signEvent(event, [current.privateKey])
    expect(verifyRotate({ event, sigs }, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })
})
