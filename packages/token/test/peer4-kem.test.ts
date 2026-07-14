import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { createIdentity } from '../src/identity.js'
import { createTokenEncrypter, encryptToken } from '../src/jwe.js'
import { isPeer4 } from '../src/peer4.js'

/**
 * Pins the peer:4 KEM gap found while planning the keystore contract work.
 *
 * `createIdentity` publishes an X25519 `keyAgreement` key in the peer:4 doc, and
 * `MultiKeyIdentity.agreeKey`/`decrypt` use its private half. But `jwe.ts`'s
 * `resolveX25519Key` never reads a published agreement key: for a DID string it calls
 * `getSignatureInfo`, which parses `did:key` only, and montgomery-derives the agreement
 * key from the SIGNING key. So the published KEM key is unreachable by any sender.
 */
describe('peer:4 keyAgreement is unreachable from jwe', () => {
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

  test('createTokenEncrypter cannot encrypt to a peer:4 DID — short or long form', async () => {
    const identity = await createPeer4Identity()
    expect(() => createTokenEncrypter(identity.id)).toThrow('Invalid DID format')
    expect(() => createTokenEncrypter(identity.longForm)).toThrow('Invalid DID format')
  })

  test('the KEM key itself works — it is only the DID path that is missing', async () => {
    const identity = await createPeer4Identity()
    const kem = identity.keys.find((k) => k.purpose === 'kem')
    if (kem == null) throw new Error('expected a KEM key')

    // Encrypting to the raw published X25519 public key round-trips.
    const encrypter = createTokenEncrypter(kem.publicKey, { algorithm: 'X25519' })
    const jwe = await encryptToken(encrypter, new TextEncoder().encode('hello'))
    const decrypted = await identity.decrypt(jwe)
    expect(new TextDecoder().decode(decrypted)).toBe('hello')
  })

  test('montgomery-deriving from the signing key — what jwe does for did:key — does NOT decrypt', async () => {
    const identity = await createPeer4Identity()
    const sig = identity.keys.find((k) => k.purpose === 'sig')
    if (sig == null) throw new Error('expected a signing key')

    // This is the key a sender WOULD use if resolveX25519Key could parse peer:4:
    // toMontgomery(signing public key). It is not the published keyAgreement key.
    const derived = ed25519.utils.toMontgomery(sig.publicKey)
    const kem = identity.keys.find((k) => k.purpose === 'kem')
    if (kem == null) throw new Error('expected a KEM key')
    expect(derived).not.toEqual(kem.publicKey)

    const encrypter = createTokenEncrypter(derived, { algorithm: 'X25519' })
    const jwe = await encryptToken(encrypter, new TextEncoder().encode('hello'))
    await expect(identity.decrypt(jwe)).rejects.toThrow()
  })

  test('a single-key EdDSA did:key identity has no KEM key at all', async () => {
    const identity = await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA' }] })
    expect(isPeer4(identity.id)).toBe(false)
    // did:key senders montgomery-derive, so this DID IS encryptable to...
    const [, publicKey] = [null, identity.publicKey] as const
    const derived = ed25519.utils.toMontgomery(publicKey)
    expect(x25519.getPublicKey(ed25519.utils.toMontgomerySecret(identity.privateKey))).toEqual(
      derived,
    )
    // ...but createIdentity's agreeKey looks for a `kem` key and finds none.
    await expect(identity.agreeKey(derived)).rejects.toThrow('No KEM key in identity')
  })
})
