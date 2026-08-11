import {
  createUnsignedToken,
  isIssuerKeyNotFoundError,
  signToken,
  verifyToken,
} from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  encodeKey,
  type SignedEvent,
} from '../src/events.js'
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
