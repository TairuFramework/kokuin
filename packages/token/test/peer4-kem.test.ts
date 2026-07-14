import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { createIdentity } from '../src/identity.js'
import { createTokenEncrypter, encryptToken } from '../src/jwe.js'
import { isPeer4 } from '../src/peer4.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

describe('did:peer:4 keyAgreement', () => {
  async function createPeer4Identity() {
    return await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
  }

  test('a sig+kem identity is peer:4 and publishes a keyAgreement key', async () => {
    const identity = await createPeer4Identity()
    expect(isPeer4(identity.id)).toBe(true)
    expect(identity.doc.keyAgreement).toEqual(['#key-1'])
  })

  test('encrypting to the long form uses the published keyAgreement key', async () => {
    const identity = await createPeer4Identity()
    const encrypter = createTokenEncrypter(identity.longForm)
    expect(encrypter.recipientID).toBe(identity.id)

    const jwe = await encryptToken(encrypter, encoder.encode('hello'))
    expect(decoder.decode(await identity.decrypt(jwe))).toBe('hello')
  })

  test('the published key is used, NOT the montgomery-derived signing key', async () => {
    const identity = await createPeer4Identity()
    const sig = identity.keys.find((key) => key.purpose === 'sig')
    const kem = identity.keys.find((key) => key.purpose === 'kem')
    if (sig == null || kem == null) throw new Error('expected a sig and a kem key')

    // The two candidate keys are genuinely different, so this test can distinguish them.
    const derived = ed25519.utils.toMontgomery(sig.publicKey)
    expect(derived).not.toEqual(kem.publicKey)

    // A JWE built from the published key decrypts; one built from the derived key does not.
    const good = await encryptToken(createTokenEncrypter(identity.longForm), encoder.encode('ok'))
    expect(decoder.decode(await identity.decrypt(good))).toBe('ok')

    const bad = await encryptToken(
      createTokenEncrypter(derived, { algorithm: 'X25519' }),
      encoder.encode('ok'),
    )
    await expect(identity.decrypt(bad)).rejects.toThrow()
  })

  test('a short form throws — it carries no document to read the key from', async () => {
    const identity = await createPeer4Identity()
    expect(() => createTokenEncrypter(identity.id)).toThrow(/short form/)
  })

  test('a peer:4 identity with no keyAgreement key throws a specific error', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'sig', alg: 'EdDSA' },
      ],
    })
    expect(isPeer4(identity.id)).toBe(true)
    expect(() => createTokenEncrypter(identity.longForm)).toThrow(/no X25519 keyAgreement key/)
  })
})

describe('did:key EdDSA identities are decryptable', () => {
  test('createIdentity did:key can agree and decrypt via the birational map', async () => {
    const identity = await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA' }] })
    expect(isPeer4(identity.id)).toBe(false)

    // A sender knows only the DID, from which it montgomery-derives the agreement key.
    const jwe = await encryptToken(createTokenEncrypter(identity.id), encoder.encode('hello'))
    expect(decoder.decode(await identity.decrypt(jwe))).toBe('hello')
  })
})
