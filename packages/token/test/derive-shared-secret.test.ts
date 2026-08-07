import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { CODECS, getDID } from '../src/did.js'
import { createIdentity } from '../src/identity.js'
import { deriveSharedSecret } from '../src/jwe.js'
import { isPeer4 } from '../src/peer4.js'

describe('deriveSharedSecret()', () => {
  test('a peer:4 long form agrees with what the recipient derives', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    expect(isPeer4(identity.id)).toBe(true)

    const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(identity.longForm)
    expect(sharedSecret).toHaveLength(32)
    expect(ephemeralPublicKey).toHaveLength(32)
    expect(await identity.agreeKey(ephemeralPublicKey)).toEqual(sharedSecret)
  })

  test('a did:key EdDSA identity agrees via the birational map', async () => {
    const identity = await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA' }] })
    expect(isPeer4(identity.id)).toBe(false)

    const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(identity.id)
    expect(await identity.agreeKey(ephemeralPublicKey)).toEqual(sharedSecret)
  })

  test('a peer:4 uses the published key, NOT the montgomery-derived signing key', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const sig = identity.keys.find((key) => key.purpose === 'sig')
    const kem = identity.keys.find((key) => key.purpose === 'kem')
    if (sig == null || kem == null) throw new Error('expected a sig and a kem key')

    // The two candidate keys are genuinely different, so this test can distinguish them.
    expect(ed25519.utils.toMontgomery(sig.publicKey)).not.toEqual(kem.publicKey)
    const derivedSecret = ed25519.utils.toMontgomerySecret(sig.privateKey)

    const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(identity.longForm)
    // Recomputing against each candidate scalar shows which branch the sender took: only the
    // published KEM key reproduces the secret. This is what fails if the branch rule is ever
    // inverted — the two round-trip tests above would both still pass, because sender and
    // recipient would be wrong in the same direction.
    expect(x25519.getSharedSecret(kem.privateKey, ephemeralPublicKey)).toEqual(sharedSecret)
    expect(x25519.getSharedSecret(derivedSecret, ephemeralPublicKey)).not.toEqual(sharedSecret)
  })

  test('two calls for the same recipient produce different ephemeral keys', async () => {
    const identity = await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA' }] })
    const first = deriveSharedSecret(identity.id)
    const second = deriveSharedSecret(identity.id)
    expect(first.ephemeralPublicKey).not.toEqual(second.ephemeralPublicKey)
    expect(first.sharedSecret).not.toEqual(second.sharedSecret)
  })

  test('a peer:4 short form throws — it carries no document to read the key from', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    expect(() => deriveSharedSecret(identity.id)).toThrow(/short form/)
  })

  test('a peer:4 with no keyAgreement key throws a specific error', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'sig', alg: 'EdDSA' },
      ],
    })
    expect(isPeer4(identity.id)).toBe(true)
    expect(() => deriveSharedSecret(identity.longForm)).toThrow(/no X25519 keyAgreement key/)
  })

  test('a non-EdDSA did:key throws', () => {
    // ES256 is a supported *signature* codec but has no X25519 agreement path.
    const did = getDID(CODECS.ES256, new Uint8Array(33).fill(1))
    expect(() => deriveSharedSecret(did)).toThrow(/Unsupported DID algorithm for encryption/)
  })
})
