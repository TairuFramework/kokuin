import {
  createUnsignedToken,
  type DIDMethodResolver,
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
// backstop" — is meaningless if a rotate is equally destructive. So a key that was authoritative at
// some position *within the current generation* still verifies material the profile issued back
// then, and a generation bump is what invalidates that too.
//
// That is `resolveHistoric` / `verifyToken({ historic: true })`, and only that. Plain `resolve`
// answers from the head's `k` alone: a rotate does retire the key it rotated away *for new
// issuance*, which is the other half of what the remedy ladder needs — otherwise a thief holding a
// stolen authority key goes on minting fresh tokens until the profile resets. Both halves are
// asserted below, side by side.

const seed = new Uint8Array(32).fill(7)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const D1 = device
const D2 = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
const D3 = 'did:key:z6MkfriQZgZXhtFA6kFHzuvhLHGRDDNzGRxeLnpKmZzHwUXR'

const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const rotate = createRotate({ seed, profile: 0, did, prior: inception.event })
const rotateAgain = createRotate({ seed, profile: 0, did, prior: rotate.event })
const reset = createReset(seed, 0, 1)

function resolverFor(log: Array<SignedEvent>) {
  return createControllerResolver({ loadLog: async () => log })
}

/** A token signed by the identity the given log's head establishes. */
async function tokenFrom(log: Array<SignedEvent>) {
  return await signToken(
    createControllerIdentity({ seed, profile: 0, log }),
    createUnsignedToken({ n: 1 }),
  )
}

describe('a rotate keeps everything the profile has issued verifiable — under `historic`', () => {
  test('a token issued before a rotation still verifies after it', async () => {
    const token = await tokenFrom([inception])

    const verified = await verifyToken(token, {
      methods: [resolverFor([inception, rotate])],
      historic: true,
    })
    expect(verified.payload.iss).toBe(did)
    // The token names the key that signed it, and that key is no longer the head's.
    expect(token.header.kid).toBe(`#${inception.event.k[0]}`)
    expect(rotate.event.k[0]).not.toBe(inception.event.k[0])
  })

  test('a token issued two rotations ago still verifies', async () => {
    const token = await tokenFrom([inception])

    await expect(
      verifyToken(token, {
        methods: [resolverFor([inception, rotate, rotateAgain])],
        historic: true,
      }),
    ).resolves.toMatchObject({ payload: { iss: did } })
  })

  test('a token issued between two rotations still verifies', async () => {
    const token = await tokenFrom([inception, rotate])

    await expect(
      verifyToken(token, {
        methods: [resolverFor([inception, rotate, rotateAgain])],
        historic: true,
      }),
    ).resolves.toMatchObject({ payload: { iss: did } })
  })

  test('a revoke does not disturb it either', async () => {
    const revoke = createRevoke({
      seed,
      profile: 0,
      did,
      prior: rotate.event,
      target: device,
      keyPosition: { gen: 0, seq: 1 },
    })
    const token = await tokenFrom([inception])

    await expect(
      verifyToken(token, {
        methods: [resolverFor([inception, rotate, revoke])],
        historic: true,
      }),
    ).resolves.toMatchObject({ payload: { iss: did } })
  })

  test('the head key is still what a token carrying no kid resolves to', async () => {
    // Accepting an earlier key when the token names it is not the same as answering with one when
    // it names nothing. Either member returns a single key, so the default stays the head's.
    const resolver = resolverFor([inception, rotate])
    const resolved = await resolver.resolve(did, {})
    expect(encodeKey(resolved.publicKey, 'EdDSA')).toBe(rotate.event.k[0])
    const historic = await historicOf(resolver)(did, {})
    expect(encodeKey(historic.publicKey, 'EdDSA')).toBe(rotate.event.k[0])
  })
})

describe('a rotate retires the key for new issuance — plain `resolve`', () => {
  // The other half of the remedy ladder. A stolen authority key can sign a token today; if the
  // default resolution accepted it after a rotate, `rotate` would be cosmetic against a compromise
  // and only `reset` would remedy anything.
  test('a token signed by the rotated-away key is rejected by default', async () => {
    const token = await tokenFrom([inception])

    await expect(
      verifyToken(token, { methods: [resolverFor([inception, rotate])] }),
    ).rejects.toThrow(/kid names a key that is not current/)
  })

  test('the rejection is an IssuerKeyNotFoundError, like every other bad `kid`', async () => {
    const token = await tokenFrom([inception])
    const error = await verifyToken(token, {
      methods: [resolverFor([inception, rotate])],
    }).then(
      () => undefined,
      (cause: unknown) => cause,
    )
    expect(isIssuerKeyNotFoundError(error)).toBe(true)
    expect(isUnresolvableIssuerError(error)).toBe(false)
  })

  test('control: the same token against the log it was issued under verifies by default', async () => {
    // The rejection above is the rotate, not anything incidental about the token or the resolver.
    const token = await tokenFrom([inception])

    await expect(
      verifyToken(token, { methods: [resolverFor([inception])] }),
    ).resolves.toMatchObject({ payload: { iss: did } })
  })

  test('a registry whose entry publishes no `resolveHistoric` fails the historic ask closed', async () => {
    // Fail closed at the call site rather than falling back to `resolve`: the caller asked a
    // different question, and answering the stricter one in its place is only accidentally safe.
    const complete = resolverFor([inception])
    const stripped = { method: complete.method, resolve: complete.resolve }
    const token = await tokenFrom([inception])

    await expect(verifyToken(token, { methods: [stripped], historic: true })).rejects.toThrow(
      /cannot resolve historic keys/,
    )
    // Control: the identical registry entry answers the non-historic ask.
    await expect(verifyToken(token, { methods: [stripped] })).resolves.toMatchObject({
      payload: { iss: did },
    })
  })
})

describe('a reset discards the prior generation', () => {
  test('a token issued before the reset no longer verifies, even historically', async () => {
    const token = await tokenFrom([inception])

    await expect(
      verifyToken(token, { methods: [resolverFor([inception, reset])], historic: true }),
    ).rejects.toThrow(/kid names a key outside the current generation/)
  })

  test('the rejection is an IssuerKeyNotFoundError, not an unresolvable issuer', async () => {
    // The DID resolved and its log folded; only the key the token named is gone. Fail-closed
    // callers key on `UnresolvableIssuerError`, so misclassifying this would let a fabricated
    // revocation record naming this DID deny every capability it ever issued.
    const token = await tokenFrom([inception])
    const error = await verifyToken(token, {
      methods: [resolverFor([inception, reset])],
      historic: true,
    }).then(
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
      verifyToken(token, { methods: [resolverFor([inception, rotate, reset])], historic: true }),
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
  test('is rejected by both members, never resolved to the head key', async () => {
    const stranger = encodeKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)), 'EdDSA')
    const resolver = resolverFor([inception, rotate])

    await expect(resolver.resolve(did, { kid: `#${stranger}` })).rejects.toThrow(
      /kid names a key that is not current/,
    )
    await expect(historicOf(resolver)(did, { kid: `#${stranger}` })).rejects.toThrow(
      /kid names a key outside the current generation/,
    )
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

const rot1 = createRotate({ seed, profile: 0, did, prior: inception.event }) //      gen0 s1  keySeq 1
const rot2 = createRotate({ seed, profile: 0, did, prior: rot1.event }) //           gen0 s2  keySeq 2
const rev1 = createRevoke({
  seed,
  profile: 0,
  did,
  prior: rot2.event,
  target: D1,
  keyPosition: { gen: 0, seq: 2 },
}) // gen0 s3
const rev2 = createRevoke({
  seed,
  profile: 0,
  did,
  prior: rev1.event,
  target: D2,
  keyPosition: { gen: 0, seq: 2 },
}) // gen0 s4
const rot3 = createRotate({
  seed,
  profile: 0,
  did,
  prior: rev2.event,
  options: { keyPosition: { gen: 0, seq: 2 } },
}) // s5 kS3
const rot4 = createRotate({ seed, profile: 0, did, prior: reset.event }) //          gen1 s1  keySeq 1
const rev3 = createRevoke({
  seed,
  profile: 0,
  did,
  prior: rot4.event,
  target: D3,
  keyPosition: { gen: 1, seq: 1 },
}) // gen1 s2
const rot5 = createRotate({
  seed,
  profile: 0,
  did,
  prior: rev3.event,
  options: { keyPosition: { gen: 1, seq: 1 } },
}) // s3 kS2

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

/**
 * `resolveHistoric` is optional on `DIDMethodResolver` — it has to be, or every hand-rolled
 * resolver stops typechecking — but `createControllerResolver` always publishes it. Asserting that
 * here once keeps the rows below free of optional chaining, and turns "the member vanished" into
 * one loud failure rather than a row that quietly stops testing anything.
 */
function historicOf(resolver: DIDMethodResolver) {
  const member = resolver.resolveHistoric
  if (member == null) {
    throw new Error('createControllerResolver published no resolveHistoric')
  }
  return (did: string, header: { kid?: string }) => member.call(resolver, did, header)
}

const resolveHistoric = historicOf(interleavedResolver)

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
    const a = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target: D1,
      keyPosition: { gen: 0, seq: 0 },
    })
    const b = createRevoke({
      seed,
      profile: 0,
      did,
      prior: a.event,
      target: D2,
      keyPosition: { gen: 0, seq: 0 },
    })
    const c = createRotate({
      seed,
      profile: 0,
      did,
      prior: b.event,
      options: { keyPosition: { gen: 0, seq: 0 } },
    })
    const d = createRevoke({
      seed,
      profile: 0,
      did,
      prior: c.event,
      target: D3,
      keyPosition: { gen: 0, seq: 1 },
    })
    const e = createRotate({
      seed,
      profile: 0,
      did,
      prior: d.event,
      options: { keyPosition: { gen: 0, seq: 1 } },
    })
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
    test(`resolveHistoric resolves ${key.slice(0, 12)}… (current generation)`, async () => {
      const resolved = await resolveHistoric(did, { kid: `#${key}` })
      expect(encodeKey(resolved.publicKey, 'EdDSA')).toBe(key)
    })
  }

  for (const key of supersededGeneration) {
    test(`resolveHistoric rejects ${key.slice(0, 12)}… (superseded generation)`, async () => {
      const error = await resolveHistoric(did, { kid: `#${key}` }).then(
        () => undefined,
        (cause: unknown) => cause,
      )
      expect(isIssuerKeyNotFoundError(error)).toBe(true)
      expect((error as Error).message).toMatch(/outside the current generation/)
    })
  }

  // `resolve` narrows that to one key. Every generation-1 key below the head is a key the profile
  // has rotated away, and only the head's own set answers.
  for (const key of currentGeneration.slice(0, -1)) {
    test(`resolve rejects ${key.slice(0, 12)}… (rotated away, same generation)`, async () => {
      const error = await interleavedResolver.resolve(did, { kid: `#${key}` }).then(
        () => undefined,
        (cause: unknown) => cause,
      )
      expect(isIssuerKeyNotFoundError(error)).toBe(true)
      expect((error as Error).message).toMatch(/not current/)
    })
  }

  test('resolve accepts the head`s own key', async () => {
    const resolved = await interleavedResolver.resolve(did, { kid: `#${keyAt(1, 2)}` })
    expect(encodeKey(resolved.publicKey, 'EdDSA')).toBe(keyAt(1, 2))
  })

  test('a key from the *next* derivation index (pre-committed, never published) is rejected', async () => {
    // `n` commits its digest, but the key itself was never in any `k` — the nearest miss a scan
    // over the generation could wrongly admit.
    await expect(resolveHistoric(did, { kid: `#${keyAt(1, 3)}` })).rejects.toThrow(
      /outside the current generation/,
    )
    await expect(interleavedResolver.resolve(did, { kid: `#${keyAt(1, 3)}` })).rejects.toThrow(
      /not current/,
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
      const error = await verifyToken(token, {
        methods: [interleavedResolver],
        historic: true,
      }).then(
        () => undefined,
        (cause: unknown) => cause,
      )
      expect(isIssuerKeyNotFoundError(error), `cut ${cut}`).toBe(true)
      expect(isUnresolvableIssuerError(error), `cut ${cut}`).toBe(false)
    }
  })

  test('a token minted at every post-reset position still verifies historically', async () => {
    for (const cut of [7, 8, 9, 10]) {
      const token = await tokenFrom(interleaved.slice(0, cut))
      await expect(
        verifyToken(token, { methods: [interleavedResolver], historic: true }),
        `cut ${cut}`,
      ).resolves.toMatchObject({ payload: { iss: did } })
    }
  })

  test('by default only the head`s own position verifies', async () => {
    // cut 10 is the whole log, so its identity signs with the head key; every earlier cut names a
    // key the log has rotated away.
    for (const cut of [7, 8, 9]) {
      const token = await tokenFrom(interleaved.slice(0, cut))
      const error = await verifyToken(token, { methods: [interleavedResolver] }).then(
        () => undefined,
        (cause: unknown) => cause,
      )
      expect(isIssuerKeyNotFoundError(error), `cut ${cut}`).toBe(true)
    }
    const head = await tokenFrom(interleaved)
    await expect(verifyToken(head, { methods: [interleavedResolver] })).resolves.toMatchObject({
      payload: { iss: did },
    })
  })
})
