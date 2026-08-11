import {
  createUnsignedToken,
  isIssuerKeyNotFoundError,
  isUnresolvableIssuerError,
  signToken,
  verifyToken,
} from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  encodeKey,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { createControllerIdentity } from '../src/identity.js'
import { createControllerResolver } from '../src/resolver.js'

// A `rotate` is routine hygiene; a `reset` is the recovery hammer. The spec reserves "discards
// everything under the prior generation, including every capability minted there" for `reset`
// specifically, and its remedy ladder — "a cold `rotate` clearing the deny set, with `reset` as the
// backstop" — is meaningless if a rotate is equally destructive. So `resolve` accepts any key that
// was authoritative at some position *within the current generation*, and a generation bump is what
// invalidates.

const seed = new Uint8Array(32).fill(7)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const D1 = device
const D2 = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
const D3 = 'did:key:z6MkfriQZgZXhtFA6kFHzuvhLHGRDDNzGRxeLnpKmZzHwUXR'

const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const rotate = createRotate(seed, 0, did, inception.event)
const rotateAgain = createRotate(seed, 0, did, rotate.event)
const reset = createReset(seed, 0, 1)

function resolverFor(log: Array<SignedEvent>) {
  return createControllerResolver({ loadLog: async () => log })
}

/** A token signed by the identity the given log's head establishes. */
async function tokenFrom(log: Array<SignedEvent>) {
  return await signToken(createControllerIdentity(seed, 0, log), createUnsignedToken({ n: 1 }))
}

describe('a rotate keeps everything the profile has issued verifiable', () => {
  test('a token issued before a rotation still verifies after it', async () => {
    const token = await tokenFrom([inception])

    const verified = await verifyToken(token, { methods: [resolverFor([inception, rotate])] })
    expect(verified.payload.iss).toBe(did)
    // The token names the key that signed it, and that key is no longer the head's.
    expect(token.header.kid).toBe(`#${inception.event.k[0]}`)
    expect(rotate.event.k[0]).not.toBe(inception.event.k[0])
  })

  test('a token issued two rotations ago still verifies', async () => {
    const token = await tokenFrom([inception])

    await expect(
      verifyToken(token, { methods: [resolverFor([inception, rotate, rotateAgain])] }),
    ).resolves.toMatchObject({ payload: { iss: did } })
  })

  test('a token issued between two rotations still verifies', async () => {
    const token = await tokenFrom([inception, rotate])

    await expect(
      verifyToken(token, { methods: [resolverFor([inception, rotate, rotateAgain])] }),
    ).resolves.toMatchObject({ payload: { iss: did } })
  })

  test('a revoke does not disturb it either', async () => {
    const revoke = createRevoke(seed, 0, did, rotate.event, device, { gen: 0, seq: 1 })
    const token = await tokenFrom([inception])

    await expect(
      verifyToken(token, { methods: [resolverFor([inception, rotate, revoke])] }),
    ).resolves.toMatchObject({ payload: { iss: did } })
  })

  test('the head key is still what a token carrying no kid resolves to', async () => {
    // Accepting an earlier key when the token names it is not the same as answering with one when
    // it names nothing. `resolve` returns a single key, so the default stays the head's.
    const resolved = await resolverFor([inception, rotate]).resolve(did, {})
    expect(encodeKey(resolved.publicKey, 'EdDSA')).toBe(rotate.event.k[0])
  })
})

describe('a reset discards the prior generation', () => {
  test('a token issued before the reset no longer verifies', async () => {
    const token = await tokenFrom([inception])

    await expect(
      verifyToken(token, { methods: [resolverFor([inception, reset])] }),
    ).rejects.toThrow(/kid names a key outside the current generation/)
  })

  test('the rejection is an IssuerKeyNotFoundError, not an unresolvable issuer', async () => {
    // The DID resolved and its log folded; only the key the token named is gone. Fail-closed
    // callers key on `UnresolvableIssuerError`, so misclassifying this would let a fabricated
    // revocation record naming this DID deny every capability it ever issued.
    const token = await tokenFrom([inception])
    const error = await verifyToken(token, { methods: [resolverFor([inception, reset])] }).then(
      () => undefined,
      (cause: unknown) => cause,
    )
    expect(isIssuerKeyNotFoundError(error)).toBe(true)
  })

  test('a key from the prior generation is rejected even mid-generation', async () => {
    // Not just the inception's key: a key established by a *rotate* under generation 0 is equally
    // gone once the generation bumps.
    const token = await tokenFrom([inception, rotate])

    await expect(
      verifyToken(token, { methods: [resolverFor([inception, rotate, reset])] }),
    ).rejects.toThrow(/kid names a key outside the current generation/)
  })

  test('a token issued after the reset verifies', async () => {
    // Control: the reset log is not simply unusable — the new generation's keys resolve.
    const log = [inception, reset]
    const token = await tokenFrom(log)

    await expect(verifyToken(token, { methods: [resolverFor(log)] })).resolves.toMatchObject({
      payload: { iss: did },
    })
  })
})

describe('a kid naming a key this profile never published', () => {
  test('is rejected, never resolved to the head key', async () => {
    const stranger = encodeKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)), 'EdDSA')

    await expect(
      resolverFor([inception, rotate]).resolve(did, { kid: `#${stranger}` }),
    ).rejects.toThrow(/kid names a key outside the current generation/)
  })

  test('a bare key without the leading `#` is still not a second spelling', async () => {
    await expect(
      resolverFor([inception, rotate]).resolve(did, { kid: inception.event.k[0] }),
    ).rejects.toThrow(/kid is not a key fragment/)
  })
})

// ---------------------------------------------------------------------------------------------
// A log where the generation boundary is *not* where a naive reading puts it: rotates, then two
// revokes (which advance `s` without establishing a key), then a rotate, then a reset, then more
// events on the far side of the boundary. The two-rotate logs above only approach this.

const rot1 = createRotate(seed, 0, did, inception.event) //      gen0 s1  keySeq 1
const rot2 = createRotate(seed, 0, did, rot1.event) //           gen0 s2  keySeq 2
const rev1 = createRevoke(seed, 0, did, rot2.event, D1, { gen: 0, seq: 2 }) // gen0 s3
const rev2 = createRevoke(seed, 0, did, rev1.event, D2, { gen: 0, seq: 2 }) // gen0 s4
const rot3 = createRotate(seed, 0, did, rev2.event, { keyPosition: { gen: 0, seq: 2 } }) // s5 kS3
const rot4 = createRotate(seed, 0, did, reset.event) //          gen1 s1  keySeq 1
const rev3 = createRevoke(seed, 0, did, rot4.event, D3, { gen: 1, seq: 1 }) // gen1 s2
const rot5 = createRotate(seed, 0, did, rev3.event, { keyPosition: { gen: 1, seq: 1 } }) // s3 kS2

const interleaved: Array<SignedEvent> = [
  inception,
  rot1,
  rot2,
  rev1,
  rev2,
  rot3,
  reset,
  rot4,
  rev3,
  rot5,
]
const interleavedResolver = resolverFor(interleaved)

const keyAt = (gen: number, seq: number) =>
  encodeKey(deriveKeyPair(seed, authorityPath(0, gen, seq), 'EdDSA').publicKey, 'EdDSA')

describe('every event in a revoke/rotate/reset interleaving folds', () => {
  test('the whole log folds', () => {
    expect(foldLog(did, interleaved).ok).toBe(true)
  })

  test('each state names the key the log actually committed', () => {
    const result = foldLog(did, interleaved)
    if (!result.ok) throw new Error(`did not fold: ${result.reason} at ${result.index}`)
    const seen = result.states.map((state) => ({
      gen: state.gen,
      seq: state.seq,
      keyGen: state.keyGen,
      keySeq: state.keySeq,
      key: state.keys[0],
    }))
    expect(seen).toEqual([
      { gen: 0, seq: 0, keyGen: 0, keySeq: 0, key: keyAt(0, 0) },
      { gen: 0, seq: 1, keyGen: 0, keySeq: 1, key: keyAt(0, 1) },
      { gen: 0, seq: 2, keyGen: 0, keySeq: 2, key: keyAt(0, 2) },
      { gen: 0, seq: 3, keyGen: 0, keySeq: 2, key: keyAt(0, 2) },
      { gen: 0, seq: 4, keyGen: 0, keySeq: 2, key: keyAt(0, 2) },
      { gen: 0, seq: 5, keyGen: 0, keySeq: 3, key: keyAt(0, 3) },
      { gen: 1, seq: 0, keyGen: 1, keySeq: 0, key: keyAt(1, 0) },
      { gen: 1, seq: 1, keyGen: 1, keySeq: 1, key: keyAt(1, 1) },
      { gen: 1, seq: 2, keyGen: 1, keySeq: 1, key: keyAt(1, 1) },
      { gen: 1, seq: 3, keyGen: 1, keySeq: 2, key: keyAt(1, 2) },
    ])
  })

  test('the head deny set is exactly the current generation`s', () => {
    const result = foldLog(did, interleaved)
    if (!result.ok) throw new Error('no fold')
    expect([...result.states[9].deny]).toEqual([D3])
    // and the pre-reset positions still deny what they denied
    expect([...result.states[4].deny].sort()).toEqual([D1, D2].sort())
  })

  test('a revoke twice, a rotate, a revoke, a rotate all inside one generation folds', () => {
    // The same shape without a reset in the way — the case F-1 names.
    const a = createRevoke(seed, 0, did, inception.event, D1, { gen: 0, seq: 0 })
    const b = createRevoke(seed, 0, did, a.event, D2, { gen: 0, seq: 0 })
    const c = createRotate(seed, 0, did, b.event, { keyPosition: { gen: 0, seq: 0 } })
    const d = createRevoke(seed, 0, did, c.event, D3, { gen: 0, seq: 1 })
    const e = createRotate(seed, 0, did, d.event, { keyPosition: { gen: 0, seq: 1 } })
    const result = foldLog(did, [inception, a, b, c, d, e])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states.map((state) => state.keySeq)).toEqual([0, 0, 0, 1, 1, 2])
    expect(result.states[5].keys[0]).toBe(keyAt(0, 2))
    expect([...result.states[5].deny].sort()).toEqual([D1, D2, D3].sort())
  })
})

describe('the accepted key set is exactly the current generation`s', () => {
  const currentGeneration = [keyAt(1, 0), keyAt(1, 1), keyAt(1, 2)]
  const supersededGeneration = [keyAt(0, 0), keyAt(0, 1), keyAt(0, 2), keyAt(0, 3)]

  for (const key of currentGeneration) {
    test(`resolves ${key.slice(0, 12)}… (current generation)`, async () => {
      const resolved = await interleavedResolver.resolve(did, { kid: `#${key}` })
      expect(encodeKey(resolved.publicKey, 'EdDSA')).toBe(key)
    })
  }

  for (const key of supersededGeneration) {
    test(`rejects ${key.slice(0, 12)}… (superseded generation)`, async () => {
      const error = await interleavedResolver.resolve(did, { kid: `#${key}` }).then(
        () => undefined,
        (cause: unknown) => cause,
      )
      expect(isIssuerKeyNotFoundError(error)).toBe(true)
      expect((error as Error).message).toMatch(/outside the current generation/)
    })
  }

  test('a key from the *next* derivation index (pre-committed, never published) is rejected', async () => {
    // `n` commits its digest, but the key itself was never in any `k` — the nearest miss a scan
    // over the generation could wrongly admit.
    await expect(interleavedResolver.resolve(did, { kid: `#${keyAt(1, 3)}` })).rejects.toThrow(
      /outside the current generation/,
    )
  })

  test('no kid still resolves to the head key only', async () => {
    const resolved = await interleavedResolver.resolve(did, {})
    expect(encodeKey(resolved.publicKey, 'EdDSA')).toBe(keyAt(1, 2))
  })
})

describe('real tokens across the boundary', () => {
  test('a token minted at every pre-reset position fails with IssuerKeyNotFound, not Unresolvable', async () => {
    for (const cut of [1, 2, 3, 4, 5, 6]) {
      const token = await tokenFrom(interleaved.slice(0, cut))
      const error = await verifyToken(token, { methods: [interleavedResolver] }).then(
        () => undefined,
        (cause: unknown) => cause,
      )
      expect(isIssuerKeyNotFoundError(error), `cut ${cut}`).toBe(true)
      expect(isUnresolvableIssuerError(error), `cut ${cut}`).toBe(false)
    }
  })

  test('a token minted at every post-reset position still verifies', async () => {
    for (const cut of [7, 8, 9, 10]) {
      const token = await tokenFrom(interleaved.slice(0, cut))
      await expect(
        verifyToken(token, { methods: [interleavedResolver] }),
        `cut ${cut}`,
      ).resolves.toMatchObject({ payload: { iss: did } })
    }
  })
})
