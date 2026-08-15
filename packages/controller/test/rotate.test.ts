import { describe, expect, test } from 'vitest'

import { canonicalBytes, digestOf } from '../src/canonical.js'
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

describe('createRotate() refuses to emit an event the fold would reject', () => {
  // `keyPosition` is where the currently-active authority key lives, and it decides which key gets
  // derived. Defaulted from `prior.s`, it is right only while the log's sequence and its derivation
  // index still coincide — and a `rev` advances `s` while establishing no key, so after the first
  // revoke of a generation they part company and never rejoin. A wrong position produced a
  // well-formed, correctly signed event that no fold would ever accept, and said nothing at emit
  // time. It is checked here against `prior`'s own pre-rotation commitment, which is in the
  // argument already.
  const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

  test('the default is refused on a rotate chained onto a revoke', () => {
    const { inception, did } = setup()
    const rev = createRevoke(seed, 0, did, inception.event, target, { gen: 0, seq: 0 })

    expect(() => createRotate(seed, 0, did, rev.event)).toThrow(/pre-commits no key/)
    // Control: the same rotate with the position the fold would name folds cleanly, so what was
    // refused is the missing position and not the shape of the log.
    const good = createRotate(seed, 0, did, rev.event, { keyPosition: { gen: 0, seq: 0 } })
    expect(foldLog(did, [inception, rev, good]).ok).toBe(true)
  })

  test('the default is refused on a rotate two events past a revoke, not just the next one', () => {
    // The case a "pass it after a revoke" rule misses: `s` stays ahead of the derivation index for
    // the rest of the generation, so this rotate's prior is an ordinary `rot` and the default is
    // still wrong. Here it is caught by the commitment rather than by the missing-`n` rule.
    const { inception, did } = setup()
    const rev = createRevoke(seed, 0, did, inception.event, target, { gen: 0, seq: 0 })
    const rot = createRotate(seed, 0, did, rev.event, { keyPosition: { gen: 0, seq: 0 } })

    expect(() => createRotate(seed, 0, did, rot.event)).toThrow(/pre-committed/)
    const good = createRotate(seed, 0, did, rot.event, { keyPosition: { gen: 0, seq: 1 } })
    expect(foldLog(did, [inception, rev, rot, good]).ok).toBe(true)
  })

  test('an explicitly wrong position is refused too, not only a defaulted one', () => {
    const { inception, did } = setup()

    expect(() =>
      createRotate(seed, 0, did, inception.event, { keyPosition: { gen: 0, seq: 5 } }),
    ).toThrow(/pre-committed/)
    expect(() =>
      createRotate(seed, 0, did, inception.event, { keyPosition: { gen: 1, seq: 0 } }),
    ).toThrow(/pre-committed/)
    // Control: the right position — which is also the default here — emits and folds.
    expect(
      foldLog(did, [
        inception,
        createRotate(seed, 0, did, inception.event, { keyPosition: { gen: 0, seq: 0 } }),
      ]).ok,
    ).toBe(true)
  })

  test('every position of a revoke-heavy generation emits, and the whole log folds', () => {
    // The end this exists for: a log stays rotatable after any number of revokes, and the deny-set
    // snapshot — the "cold rotate" of the remedy ladder — rides on exactly such a rotate.
    const { inception, did } = setup()
    const a = createRevoke(seed, 0, did, inception.event, target, { gen: 0, seq: 0 })
    const b = createRevoke(seed, 0, did, a.event, `${target}2`, { gen: 0, seq: 0 })
    const cold = createRotate(seed, 0, did, b.event, { keyPosition: { gen: 0, seq: 0 }, deny: [] })
    const c = createRevoke(seed, 0, did, cold.event, `${target}3`, { gen: 0, seq: 1 })
    const last = createRotate(seed, 0, did, c.event, { keyPosition: { gen: 0, seq: 1 } })

    const result = foldLog(did, [inception, a, b, cold, c, last])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states.map((state) => state.keySeq)).toEqual([0, 0, 0, 1, 1, 2])
  })

  test('a seed that is not the log`s root is left alone — the fold is that layer', () => {
    // The check asks "will my own log reject this", which has no answer for a profile this seed
    // never inceptioned: the commitment was written by other key material entirely, so a mismatch
    // says nothing about the position. Building a foreign rotate is something the conformance
    // suite legitimately does, and the fold is what refuses it.
    const { inception, did } = setup()
    const foreign = new Uint8Array(32).fill(9)

    const forged = createRotate(foreign, 0, did, inception.event)
    expect(forged.event.t).toBe('rot')
    expect(foldLog(did, [inception, forged])).toEqual({
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
    const base = createRotate(seed, 0, did, inception.event)
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
      expect(foldLog(did, [inception, signed])).toEqual({
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
    expect(foldLog(did, [inception, signed]).ok).toBe(true)

    const sealed = createRotate(seed, 0, did, inception.event, { seal: 'zSomeExternalDigest' })
    expect(sealed.event.a).toBe('zSomeExternalDigest')
    const plain = createRotate(seed, 0, did, inception.event)
    expect(plain.event.a).toBeUndefined()
    // The member is present-and-undefined on the object and absent from the encoding — the
    // canonicalizer drops undefined members — so a sealless rotate's digest does not depend on it.
    expect(new TextDecoder().decode(canonicalBytes(plain.event))).not.toContain('"a"')
  })
})
