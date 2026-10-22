import { describe, expect, test } from 'vitest'

import { canonicalBytes, digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRotate,
  didFromInception,
  type SignedEvent,
  signEvent,
  verifyRotate,
  verifySignatures,
} from '../src/events.js'
import { foldLog, keyStateAt } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const seed = new Uint8Array(32).fill(1)

function setup() {
  const inception = createInception(seed, 0)
  const did = didFromInception(inception.event)
  return { inception, did, priorDigest: digestOf(inception.event) }
}

describe('createRotate()', () => {
  test('advances the sequence and keeps the generation', () => {
    const { inception, did } = setup()
    const { event } = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    expect(event.s).toBe(1)
    expect(event.g).toBe(0)
  })

  test('names the DID explicitly, unlike inception', () => {
    const { inception, did } = setup()
    expect(
      createRotate({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        snapshot: { members: [], deny: [] },
      }).event.i,
    ).toBe(did)
  })

  test('chains to the previous event by digest', () => {
    const { inception, did, priorDigest } = setup()
    expect(
      createRotate({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        snapshot: { members: [], deny: [] },
      }).event.p,
    ).toBe(priorDigest)
  })

  test('reveals the keys the prior event pre-committed', () => {
    const { inception, did } = setup()
    const { event } = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    expect(digestOf(event.k[0])).toBe(inception.event.n[0])
  })

  test('is reproducible from the seed when it carries no optional fields', () => {
    const { inception, did } = setup()
    expect(
      createRotate({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        snapshot: { members: [], deny: [] },
      }),
    ).toEqual(
      createRotate({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        snapshot: { members: [], deny: [] },
      }),
    )
  })

  test('carries a seal when one is given', () => {
    const { inception, did } = setup()
    const seal = digestOf({ grant: 'management' })
    expect(
      createRotate({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        seal,
        snapshot: { members: [], deny: [] },
      }).event.a,
    ).toBe(seal)
  })

  test('carries the state snapshot it is given, as `m` and `d`', () => {
    const { inception, did } = setup()
    const deny = ['did:key:zStolen']
    const { event } = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny },
    })
    expect(event.d).toEqual(deny)
    expect(event.m).toEqual([])
  })

  test('a rotate chained onto a rotate reveals the key the log pre-committed, at its own `s`', () => {
    // The root chain holds only key-establishing events, so the derivation index of each rotate's
    // key is its sequence: no position to pass, and none to get wrong.
    const { inception, did } = setup()
    const log: Array<SignedEvent> = [inception]
    let prior: SignedEvent['event'] = inception.event
    for (let i = 0; i < 4; i++) {
      const rot = createRotate({
        seed,
        profile: 0,
        did,
        prior,
        snapshot: { members: [], deny: [] },
      })
      log.push(rot)
      prior = rot.event
    }
    const result = foldLog(did, { chain: log, events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states.map((state) => state.keySeq)).toEqual([0, 1, 2, 3, 4])
    expect(result.states.map((state) => state.seq)).toEqual([0, 1, 2, 3, 4])
    expect(keyStateAt(result, 4)?.keys).toEqual([
      encodeKey(deriveKeyPair(seed, authorityPath(0, 0, 4), 'EdDSA').publicKey, 'EdDSA'),
    ])
  })
})

describe('verifyRotate()', () => {
  test('accepts a rotate signed by the pre-committed next keys', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    expect(verifyRotate(signed, { digest: priorDigest, n: inception.event.n })).toBe(true)
  })

  test('rejects a rotate whose keys were not pre-committed — a stolen device cannot rotate', () => {
    const { inception, did, priorDigest } = setup()
    const other = new Uint8Array(32).fill(9)
    const signed = createRotate({
      seed: other,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    expect(verifyRotate(signed, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })

  test('rejects a rotate that does not chain to the prior digest', () => {
    const { inception, did } = setup()
    const signed = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    expect(verifyRotate(signed, { digest: digestOf({ other: true }), n: inception.event.n })).toBe(
      false,
    )
  })

  test('rejects a tampered state snapshot — both halves are covered by the signature', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const injected = { did: 'did:key:zInjected', key: 'zInjected', add: 'zAdd', lease: 1 }
    for (const patch of [{ d: ['did:key:zInjected'] }, { m: [injected] }]) {
      const tampered = { ...signed, event: { ...signed.event, ...patch } }
      expect(verifyRotate(tampered, { digest: priorDigest, n: inception.event.n })).toBe(false)
    }
    // Control: the untouched event verifies.
    expect(verifyRotate(signed, { digest: priorDigest, n: inception.event.n })).toBe(true)
  })

  test('rejects a key presented as an authority key when it is X25519-tagged, not EdDSA', () => {
    // A caller must not be able to present a key agreement key as an authority key by swapping
    // the tag a verifier trusts without checking. Mistagging the real authority key (rather than
    // substituting a different one, or reusing the original signature) and re-signing with its
    // real private key gives a genuinely valid Ed25519 signature over these exact bytes — so this
    // only fails if verification checks the tag, not just whether the signature verifies.
    const { inception, did } = setup()
    const signed = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
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
    const signed = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const current = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
    const event = { ...signed.event, ka: [] }
    const sigs = signEvent(event, [current.privateKey])
    expect(verifyRotate({ event, sigs }, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })

  test('rejects a rotate whose ka holds a key that is not X25519-tagged', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const current = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
    const event = { ...signed.event, ka: [at(signed.event.k, 0)] }
    const sigs = signEvent(event, [current.privateKey])
    expect(verifyRotate({ event, sigs }, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })
})

describe('createRotate() refuses to emit an event the fold would reject', () => {
  // The key a rotate reveals is derived one past `prior`'s position and must be the one `prior`
  // committed in `n`. For a prior that is an event of this seed's own log that always holds; a
  // hand-built prior is where it does not, and a well-formed, correctly signed event no fold would
  // accept is worse than a throw at emit time.
  const snapshot = { members: [], deny: [] }

  test('a prior that commits no key is refused', () => {
    const { inception, did } = setup()
    const { n: _n, ...uncommitted } = inception.event
    expect(() => createRotate({ seed, profile: 0, did, prior: uncommitted, snapshot })).toThrow(
      /pre-commits no key/,
    )
  })

  test('a prior committing a key other than the one derived at its next position is refused', () => {
    const { inception, did } = setup()
    const elsewhere = { ...inception.event, n: [digestOf('a key nothing derives')] }
    expect(() => createRotate({ seed, profile: 0, did, prior: elsewhere, snapshot })).toThrow(
      /pre-committed/,
    )
    // Control: the real prior emits and folds.
    const good = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot,
    })
    expect(foldLog(did, { chain: [inception, good], events: [] }).ok).toBe(true)
  })

  test('a seed that is not the log`s root is left alone — the fold is that layer', () => {
    // The check asks "will my own log reject this", which has no answer for a profile this seed
    // never inceptioned: the commitment was written by other key material entirely, so a mismatch
    // says nothing about the position. Building a foreign rotate is something the conformance
    // suite legitimately does, and the fold is what refuses it.
    const { inception, did } = setup()
    const foreign = new Uint8Array(32).fill(9)

    const forged = createRotate({
      seed: foreign,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    expect(forged.event.t).toBe('rot')
    expect(foldLog(did, { chain: [inception, forged], events: [] })).toEqual({
      ok: false,
      reason: 'invalid rotate',
      index: 1,
    })
  })
})

describe('a rotate`s thresholds and seal are checked', () => {
  // The rotate half of what `inception.test.ts` pins for an inception, plus the seal. `a` stays
  // opaque to the fold by design — its meaning belongs to whatever anchored it, and no key state
  // can contradict it — but it is a digest string on the wire, so a reader that finds one can read
  // it as one.
  function rotateWith(patch: Record<string, unknown>) {
    const { inception, did, priorDigest } = setup()
    const base = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const event = { ...base.event, ...patch } as unknown as typeof base.event
    const key = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
    return {
      signed: { event, sigs: signEvent(event, [key.privateKey]) },
      prior: { digest: priorDigest, n: inception.event.n },
      did,
      inception,
    }
  }

  for (const patch of [
    { kt: 0 },
    { kt: 2 },
    { kt: '1' },
    { kt: null },
    { kt: undefined },
    { nt: 0 },
    { nt: 2 },
    { nt: null },
    { a: 42 },
    { a: {} },
    { a: ['zAbc'] },
    { a: true },
  ]) {
    test(`a rotate carrying ${JSON.stringify(patch)} is rejected`, () => {
      const { signed, prior, did, inception } = rotateWith(patch)
      expect(verifyRotate(signed, prior)).toBe(false)
      expect(foldLog(did, { chain: [inception, signed], events: [] })).toEqual({
        ok: false,
        reason: 'invalid rotate',
        index: 1,
      })
    })
  }

  test('control: a well-formed seal is carried through, and an absent one is not `null`', () => {
    // Both arms of the seal check, so what the rows above reject is the type. And the generator's
    // own output never encodes an absent `a` at all — `canonicalize` drops undefined members — so
    // the digest of a sealless rotate does not depend on the member existing.
    const { signed, prior, did, inception } = rotateWith({ a: 'zSomeExternalDigest' })
    expect(verifyRotate(signed, prior)).toBe(true)
    expect(foldLog(did, { chain: [inception, signed], events: [] }).ok).toBe(true)

    const sealed = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      seal: 'zSomeExternalDigest',
      snapshot: { members: [], deny: [] },
    })
    expect(sealed.event.a).toBe('zSomeExternalDigest')
    const plain = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    expect(plain.event.a).toBeUndefined()
    // The member is present-and-undefined on the object and absent from the encoding — the
    // canonicalizer drops undefined members — so a sealless rotate's digest does not depend on it.
    expect(new TextDecoder().decode(canonicalBytes(plain.event))).not.toContain('"a"')
  })
})
