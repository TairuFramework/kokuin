import { createTokenEncrypter, decryptToken, encryptToken } from '@kokuin/jwe'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { getAgreementKey } from '../src/did.js'
import { createIdentity } from '../src/identity.js'
import { encodeMultibase } from '../src/multibase.js'
import type { DIDDoc } from '../src/peer4.js'
import { encodePeer4, isPeer4 } from '../src/peer4.js'

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
    expect(decoder.decode(await decryptToken(identity, jwe))).toBe('hello')
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
    expect(decoder.decode(await decryptToken(identity, good))).toBe('ok')

    const bad = await encryptToken(
      createTokenEncrypter(derived, { algorithm: 'X25519' }),
      encoder.encode('ok'),
    )
    await expect(decryptToken(identity, bad)).rejects.toThrow()
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
    expect(decoder.decode(await decryptToken(identity, jwe))).toBe('hello')
  })
})

describe('getAgreementKey() bounds and skips bad entries', () => {
  function x25519Multibase() {
    const codec = new Uint8Array([0xec, 0x01])
    const priv = x25519.utils.randomSecretKey()
    const pub = x25519.getPublicKey(priv)
    const tagged = new Uint8Array(codec.length + pub.length)
    tagged.set(codec, 0)
    tagged.set(pub, codec.length)
    return encodeMultibase(tagged)
  }

  test('an oversized publicKeyMultibase is rejected fast, not decoded', () => {
    // base58.decode is O(n^2): if this were decoded rather than length-checked away, a string
    // this size would burn tens to hundreds of milliseconds of synchronous CPU (measured ~79ms
    // for a 3.8 KiB key). Bounded, resolving it costs nothing.
    const doc: DIDDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-0', type: 'Multikey', publicKeyMultibase: `z${'1'.repeat(100_000)}` },
      ],
      keyAgreement: ['#key-0'],
    }

    const start = performance.now()
    const result = getAgreementKey(doc)
    const elapsed = performance.now() - start

    expect(result).toBeNull()
    expect(elapsed).toBeLessThan(20)
  })

  test('an undecodable keyAgreement entry before a good one still resolves the good one', () => {
    const doc: DIDDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        // 'm' is a legal DID Core multibase prefix (base64) that this codebase doesn't support.
        { id: '#key-bad', type: 'Multikey', publicKeyMultibase: 'mAAAA' },
        { id: '#key-good', type: 'Multikey', publicKeyMultibase: x25519Multibase() },
      ],
      keyAgreement: ['#key-bad', '#key-good'],
    }

    expect(getAgreementKey(doc)).not.toBeNull()
  })

  test('a wrong-length X25519 key is skipped, not returned or thrown', () => {
    const codec = new Uint8Array([0xec, 0x01])
    const shortKey = new Uint8Array(16) // half the expected 32 bytes
    const tagged = new Uint8Array(codec.length + shortKey.length)
    tagged.set(codec, 0)
    tagged.set(shortKey, codec.length)

    const doc: DIDDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-0', type: 'Multikey', publicKeyMultibase: encodeMultibase(tagged) },
      ],
      keyAgreement: ['#key-0'],
    }

    expect(getAgreementKey(doc)).toBeNull()
  })

  test('createTokenEncrypter surfaces the wrong-length case as "no keyAgreement key", not a noble RangeError', () => {
    const codec = new Uint8Array([0xec, 0x01])
    const shortKey = new Uint8Array(16) // half the expected 32 bytes
    const tagged = new Uint8Array(codec.length + shortKey.length)
    tagged.set(codec, 0)
    tagged.set(shortKey, codec.length)

    const { longForm } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-0', type: 'Multikey', publicKeyMultibase: encodeMultibase(tagged) },
      ],
      keyAgreement: ['#key-0'],
    })

    expect(() => createTokenEncrypter(longForm)).toThrow(/no X25519 keyAgreement key/)
  })
})
