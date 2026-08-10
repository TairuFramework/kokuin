import { createTokenEncrypterAsync, decryptToken, encryptToken } from '@kokuin/jwe'
import { x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { agreementPath, deriveKeyPair } from '../src/derivation.js'
import { createInception, createRotate, didFromInception } from '../src/events.js'
import { createControllerResolver } from '../src/resolver.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

describe('encrypting to a did:kokuin: profile', () => {
  test('round-trips through a real folded log', async () => {
    const seed = new Uint8Array(32).fill(3)
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const resolver = createControllerResolver({ loadLog: async () => [inception] })

    const encrypter = await createTokenEncrypterAsync(did, { methods: [resolver] })
    const jwe = await encryptToken(encrypter, encoder.encode('hello'))

    // The recipient side: the profile holder derives the same agreement key from the seed.
    const agreement = deriveKeyPair(seed, agreementPath(0, 0, 0), 'X25519')
    const recipient = {
      id: did as `did:${string}:${string}`,
      agreeKey: async (ephemeralPublicKey: Uint8Array) =>
        x25519.getSharedSecret(agreement.privateKey, ephemeralPublicKey),
    }

    expect(decoder.decode(await decryptToken(recipient, jwe))).toBe('hello')
  })

  test('a rotation moves the encryption target', async () => {
    const seed = new Uint8Array(32).fill(3)
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate(seed, 0, did, inception.event)
    const resolver = createControllerResolver({ loadLog: async () => [inception, rotate] })

    const encrypter = await createTokenEncrypterAsync(did, { methods: [resolver] })
    const jwe = await encryptToken(encrypter, encoder.encode('hello, rotated'))

    // The rotated agreement key opens the ciphertext.
    const rotatedAgreement = deriveKeyPair(seed, agreementPath(0, 0, 1), 'X25519')
    const rotatedRecipient = {
      id: did as `did:${string}:${string}`,
      agreeKey: async (ephemeralPublicKey: Uint8Array) =>
        x25519.getSharedSecret(rotatedAgreement.privateKey, ephemeralPublicKey),
    }
    expect(decoder.decode(await decryptToken(rotatedRecipient, jwe))).toBe('hello, rotated')

    // The inception's superseded agreement key must NOT open it — an implementation that
    // resolved `ka` off the inception rather than the folded state would pass without this.
    const inceptionAgreement = deriveKeyPair(seed, agreementPath(0, 0, 0), 'X25519')
    const inceptionRecipient = {
      id: did as `did:${string}:${string}`,
      agreeKey: async (ephemeralPublicKey: Uint8Array) =>
        x25519.getSharedSecret(inceptionAgreement.privateKey, ephemeralPublicKey),
    }
    await expect(decryptToken(inceptionRecipient, jwe)).rejects.toThrow()
  })
})
