import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  encodeKey,
  signEvent,
  verifyRotate,
  verifySignatures,
} from '../src/events.js'
import { foldLog, keyStateAt } from '../src/fold.js'

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

  test('a rotate chained onto a revoke reveals the key the log actually pre-committed', () => {
    // Amendment A, on the rotate side. A revoke advances `s` without establishing a key, so the
    // committed next key still sits one past the last icp/rot — not one past the revoke. Deriving
    // from `prior.s` reveals a key nothing ever committed, and the rotate cannot fold: after any
    // revoke the log would be permanently unrotatable, which also makes the deny-set snapshot the
    // spec's remedy ladder is built on unreachable.
    const { inception, did } = setup()
    const revoke = createRevoke(seed, 0, did, inception.event, 'did:key:zStolen', {
      gen: 0,
      seq: 0,
    })
    const state = keyStateAt(foldLog(did, [inception, revoke]), 1)
    expect(state).toBeDefined()
    if (state == null) return

    const rotate = createRotate(seed, 0, did, revoke.event, {
      keyPosition: { gen: state.keyGen, seq: state.keySeq },
      deny: [],
    })
    expect(digestOf(rotate.event.k[0])).toBe(state.next[0])

    const folded = foldLog(did, [inception, revoke, rotate])
    expect(folded).toMatchObject({ ok: true })
    if (!folded.ok) return
    // The snapshot really replaced the accumulated set.
    expect(folded.states[1].deny.has('did:key:zStolen')).toBe(true)
    expect(folded.states[2].deny.size).toBe(0)
    // And the log keeps rotating from there, now that the key positions have diverged for good.
    const again = createRotate(seed, 0, did, rotate.event, {
      keyPosition: { gen: folded.states[2].keyGen, seq: folded.states[2].keySeq },
    })
    expect(foldLog(did, [inception, revoke, rotate, again])).toMatchObject({ ok: true })
  })

  test('without a keyPosition it still rotates from an icp or rot, where the two coincide', () => {
    // The default has to stay right for the overwhelmingly common case, which is every call site
    // in this repo.
    const { inception, did } = setup()
    const rotate = createRotate(seed, 0, did, inception.event)
    expect(foldLog(did, [inception, rotate])).toMatchObject({ ok: true })
    expect(
      createRotate(seed, 0, did, inception.event, { keyPosition: { gen: 0, seq: 0 } }),
    ).toEqual(rotate)
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
