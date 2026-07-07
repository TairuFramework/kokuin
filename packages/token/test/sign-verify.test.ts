import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { equals } from 'uint8arrays'
import { describe, expect, test } from 'vitest'

import { createFullIdentity, randomIdentity } from '../src/identity.js'
import { randomPrivateKey } from '../src/signer.js'
import { verifyToken } from '../src/token.js'
import { getVerifier } from '../src/verifier.js'

describe('createFullIdentity()', () => {
  test('returns the same id for the same private key', () => {
    const privateKey = randomPrivateKey()
    const identity1 = createFullIdentity(privateKey)
    const identity2 = createFullIdentity(privateKey)
    expect(identity2.id).toBe(identity1.id)
  })
})

describe('randomIdentity()', () => {
  test('returns a random identity', () => {
    const identity1 = randomIdentity()
    const identity2 = randomIdentity()
    expect(identity2.id).not.toBe(identity1.id)
  })
})

describe('sign and verify', () => {
  test('EdDSA round-trip via identity', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({ test: true })
    const verified = await verifyToken(token)
    expect(verified.payload.test).toBe(true)
    expect((verified.payload as Record<string, unknown>).iss).toBe(identity.id)
  })

  test('audience validation', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({ aud: 'did:key:service-a' })

    // Matching audience passes.
    await expect(verifyToken(token, { audience: 'did:key:service-a' })).resolves.toBeDefined()
    // Membership in an array of accepted audiences passes.
    await expect(
      verifyToken(token, { audience: ['did:key:other', 'did:key:service-a'] }),
    ).resolves.toBeDefined()
    // Unset audience skips the check (backward compatible).
    await expect(verifyToken(token)).resolves.toBeDefined()
    // Mismatched audience is rejected (a token for A must not verify against B).
    await expect(verifyToken(token, { audience: 'did:key:service-b' })).rejects.toThrow(/audience/)

    // A token with no aud claim is rejected when an audience is expected.
    const noAud = await identity.signToken({ test: true })
    await expect(verifyToken(noAud, { audience: 'did:key:service-a' })).rejects.toThrow(/audience/)

    // An empty accept-list rejects every token.
    await expect(verifyToken(token, { audience: [] })).rejects.toThrow(/audience/)
  })

  test('audience validation rejects unsigned and alg:none tokens', async () => {
    // Object form: an unsigned token cannot satisfy an audience requirement.
    const unsigned = { header: { typ: 'JWT', alg: 'none' }, payload: { aud: 'did:key:service-a' } }
    await expect(verifyToken(unsigned as never, { audience: 'did:key:service-a' })).rejects.toThrow(
      /requires a signed token/,
    )

    // String form with alg:none header is likewise rejected when an audience is expected.
    const header = Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'none' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ aud: 'did:key:service-a' })).toString('base64url')
    await expect(
      verifyToken(`${header}.${payload}.`, { audience: 'did:key:service-a' }),
    ).rejects.toThrow(/requires a signed token/)

    // Without an audience option, unsigned tokens still verify (unchanged behavior).
    await expect(verifyToken(unsigned as never)).resolves.toBeDefined()
  })

  test('EdDSA low-level signature', async () => {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    const message = new Uint8Array([1, 2, 3])
    const signature = ed25519.sign(message, privateKey)
    const verify = getVerifier('EdDSA')
    const verified = await verify(signature, message, publicKey)
    expect(verified).toBe(true)
    const failed = await verify(signature, message, new Uint8Array(32))
    expect(failed).toBe(false)
  })

  test('ES256 low-level signature', async () => {
    const { publicKey, secretKey } = p256.keygen()
    const message = new Uint8Array([1, 2, 3])
    const signature = p256.sign(message, secretKey)
    const verify = getVerifier('ES256')
    const verified = await verify(signature, message, publicKey)
    expect(verified).toBe(true)
    const failed = await verify(signature, message, p256.keygen().publicKey)
    expect(failed).toBe(false)
  })

  test('ES256 rejects malleable high-S signatures', async () => {
    const { publicKey, secretKey } = p256.keygen()
    const verify = getVerifier('ES256')
    // RFC 6979 nonces are deterministic per message; ~half of messages produce a
    // high-S signature when lowS normalization is disabled. Find one.
    for (let i = 0; i < 256; i++) {
      const message = new TextEncoder().encode(`malleability-${i}`)
      const lowS = p256.sign(message, secretKey, { lowS: true })
      const maybeHighS = p256.sign(message, secretKey, { lowS: false })
      if (!equals(lowS, maybeHighS)) {
        expect(await verify(lowS, message, publicKey)).toBe(true)
        expect(await verify(maybeHighS, message, publicKey)).toBe(false)
        return
      }
    }
    throw new Error('no high-S signature found in 256 attempts')
  })
})
