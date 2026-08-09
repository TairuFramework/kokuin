import { createTokenEncrypter, decryptToken, encryptToken } from '@kokuin/jwe'
import { CODECS, getDID, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createBrowserIdentity, createLegacyES256Identity } from '../src/identity.js'
import { generateKeyRecord } from '../src/utils.js'

describe('createBrowserIdentity', () => {
  test('yields a did:key EdDSA FullIdentity', async () => {
    const record = await generateKeyRecord()
    const identity = await createBrowserIdentity(record)
    expect(identity.id).toBe(getDID(CODECS.EdDSA, record.publicKey))
    expect(identity.publicKey).toEqual(record.publicKey)
  })

  test('signs tokens the @kokuin/token verifier accepts', async () => {
    const identity = await createBrowserIdentity(await generateKeyRecord())
    const token = await identity.signToken({ aud: 'did:key:zSomeone', sub: 'test' })
    expect(token.header.alg).toBe('EdDSA')
    const verified = await verifyToken(token)
    expect(verified.payload.iss).toBe(identity.id)
  })

  test('decrypts a JWE addressed to its DID — the whole point of the import mechanism', async () => {
    const identity = await createBrowserIdentity(await generateKeyRecord())

    // The sender knows only the DID. If the agreement key were independently generated, this
    // would fail — which is exactly what subtle.generateKey would have produced.
    const jwe = await encryptToken(
      createTokenEncrypter(identity.id),
      new TextEncoder().encode('secret'),
    )
    expect(new TextDecoder().decode(await decryptToken(identity, jwe))).toBe('secret')
  })

  test('rejects a payload whose iss is not this identity', async () => {
    const identity = await createBrowserIdentity(await generateKeyRecord())
    await expect(identity.signToken({ iss: 'did:key:zOther' })).rejects.toThrow(
      /issuer does not match/,
    )
  })
})

describe('createLegacyES256Identity', () => {
  async function legacyRecord(): Promise<CryptoKeyPair> {
    return (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
    ])) as CryptoKeyPair
  }

  test('yields a did:key ES256 SigningIdentity — no decrypt', async () => {
    const identity = await createLegacyES256Identity(await legacyRecord())
    expect(identity.id).toMatch(/^did:key:z/)
    expect('decrypt' in identity).toBe(false)
    expect('agreeKey' in identity).toBe(false)
  })

  test('still signs verifiable tokens, with low-S normalization', async () => {
    const identity = await createLegacyES256Identity(await legacyRecord())
    // Repeat: WebCrypto emits high-S about half the time, and the verifier runs lowS: true.
    for (let i = 0; i < 8; i++) {
      const token = await identity.signToken({ sub: `test-${i}` })
      expect(token.header.alg).toBe('ES256')
      await expect(verifyToken(token)).resolves.toBeDefined()
    }
  })
})
