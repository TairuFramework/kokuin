import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test, vi } from 'vitest'

import { assertEd25519Available, generateKeyRecord, isLegacyES256Record } from '../src/utils.js'

describe('generateKeyRecord', () => {
  test('produces non-extractable signing and agreement keys', async () => {
    const record = await generateKeyRecord()
    expect(record.suite).toBe('Ed25519')
    expect(record.signing.extractable).toBe(false)
    expect(record.agreement.extractable).toBe(false)
    expect(record.publicKey).toHaveLength(32)

    await expect(crypto.subtle.exportKey('jwk', record.signing)).rejects.toThrow()
    await expect(crypto.subtle.exportKey('jwk', record.agreement)).rejects.toThrow()
  })

  test('the agreement key is the one a sender derives from the DID — not an independent key', async () => {
    const record = await generateKeyRecord()

    // A sender knows only the Ed25519 public key (from the did:key DID) and derives the
    // agreement key from it. If the agreement key were generated independently, this ECDH
    // would not agree and nothing addressed to the DID could ever be decrypted.
    const senderPrivate = x25519.utils.randomSecretKey()
    const senderPublic = x25519.getPublicKey(senderPrivate)
    const senderShared = x25519.getSharedSecret(
      senderPrivate,
      ed25519.utils.toMontgomery(record.publicKey),
    )

    const senderKey = await crypto.subtle.importKey(
      'raw',
      senderPublic,
      { name: 'X25519' },
      true,
      [],
    )
    const ourShared = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'X25519', public: senderKey }, record.agreement, 256),
    )

    expect(ourShared).toEqual(senderShared)
  })

  test('the signing key produces signatures noble verifies', async () => {
    const record = await generateKeyRecord()
    const message = new TextEncoder().encode('hello')
    const signature = new Uint8Array(
      await crypto.subtle.sign({ name: 'Ed25519' }, record.signing, message),
    )
    expect(ed25519.verify(signature, message, record.publicKey)).toBe(true)
  })

  test('two records are distinct', async () => {
    const first = await generateKeyRecord()
    const second = await generateKeyRecord()
    expect(first.publicKey).not.toEqual(second.publicKey)
  })
})

describe('assertEd25519Available', () => {
  test('resolves where Ed25519 is supported', async () => {
    await expect(assertEd25519Available()).resolves.toBeUndefined()
  })

  test('throws — never falls back — when Ed25519 is unavailable', async () => {
    const generateKey = vi
      .spyOn(crypto.subtle, 'generateKey')
      .mockRejectedValue(new Error('Unrecognized algorithm name'))

    // A silent fallback to P-256 would mint a DIFFERENT DID for the same keyID. That is
    // identity loss, not degradation.
    await expect(assertEd25519Available()).rejects.toThrow(/Ed25519/)
    generateKey.mockRestore()
  })
})

describe('isLegacyES256Record', () => {
  test('an untagged CryptoKeyPair is legacy', async () => {
    const keyPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    )) as CryptoKeyPair
    expect(isLegacyES256Record(keyPair)).toBe(true)
  })

  test('a suite-tagged record is not legacy', async () => {
    expect(isLegacyES256Record(await generateKeyRecord())).toBe(false)
  })
})
