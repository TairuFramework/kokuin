import {
  CODECS,
  createIdentity,
  type DIDMethodResolver,
  getDID,
  isPeer4,
  type KeyAgreementIdentity,
  type ResolvedAgreementKey,
  randomIdentity,
} from '@kokuin/token'
import { x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import {
  createTokenEncrypterAsync,
  decryptToken,
  deriveSharedSecretAsync,
  encryptToken,
} from '../src/index.js'

const kokuinDID = 'did:kokuin:zTestProfile'

/** Builds a resolver-backed profile with a real X25519 agreement key, and its decrypter. */
function buildProfile(): {
  resolver: DIDMethodResolver
  profileAgreement: KeyAgreementIdentity
} {
  const agreementPrivateKey = x25519.utils.randomSecretKey()
  const agreementPublicKey = x25519.getPublicKey(agreementPrivateKey)

  const resolver: DIDMethodResolver = {
    method: 'kokuin',
    resolve: async () => {
      throw new Error('unused in this test')
    },
    async resolveAgreementKey(did: string): Promise<Array<ResolvedAgreementKey>> {
      if (did !== kokuinDID) {
        throw new Error(`Unknown DID: ${did}`)
      }
      return [{ alg: 'X25519', publicKey: agreementPublicKey }]
    },
  }

  const profileAgreement: KeyAgreementIdentity = {
    id: kokuinDID,
    async agreeKey(ephemeralPublicKey: Uint8Array): Promise<Uint8Array> {
      return x25519.getSharedSecret(agreementPrivateKey, ephemeralPublicKey)
    },
  }

  return { resolver, profileAgreement }
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

describe('createTokenEncrypterAsync()', () => {
  test('encrypts to a resolver-backed DID and round-trips', async () => {
    const { resolver, profileAgreement } = buildProfile()
    const encrypter = await createTokenEncrypterAsync(kokuinDID, { methods: [resolver] })
    expect(encrypter.recipientID).toBe(kokuinDID)

    const jwe = await encryptToken(encrypter, encoder.encode('hello'))
    expect(decoder.decode(await decryptToken(profileAgreement, jwe))).toBe('hello')
  })

  test('falls through to the sync path for a self-contained DID', async () => {
    const identity = randomIdentity()
    const encrypter = await createTokenEncrypterAsync(identity.id, { methods: [] })
    expect(encrypter.recipientID).toBe(identity.id)

    // Confirm the sync path actually ran: the encrypter agrees with what the identity derives.
    const jwe = await encryptToken(encrypter, encoder.encode('hi'))
    expect(decoder.decode(await decryptToken(identity, jwe))).toBe('hi')
  })

  test('names the method when no resolver is registered', async () => {
    await expect(createTokenEncrypterAsync(kokuinDID, { methods: [] })).rejects.toThrow(
      /no resolver registered for did:kokuin/i,
    )
  })

  test('reports a method that cannot do key agreement', async () => {
    const signOnly: DIDMethodResolver = {
      method: 'kokuin',
      resolve: async () => {
        throw new Error('unused')
      },
    }
    await expect(createTokenEncrypterAsync(kokuinDID, { methods: [signOnly] })).rejects.toThrow(
      /does not support key agreement/i,
    )
  })

  test('reports a set holding no algorithm this package supports', async () => {
    const exotic: DIDMethodResolver = {
      method: 'kokuin',
      resolve: async () => {
        throw new Error('unused')
      },
      resolveAgreementKey: async () => [
        { alg: 'ML-KEM-768' as never, publicKey: new Uint8Array(1184) },
      ],
    }
    await expect(createTokenEncrypterAsync(kokuinDID, { methods: [exotic] })).rejects.toThrow(
      /no supported key agreement algorithm/i,
    )
  })

  test('does not swallow the sync path own diagnostics for a did:peer:4 short form', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    expect(isPeer4(identity.id)).toBe(true)

    // No resolver registered for the 'peer' method, so findMethodResolver returns undefined and
    // the call falls to the sync path. That path's own precise error must survive, not be
    // replaced by a generic "no resolver registered for did:peer" message.
    await expect(createTokenEncrypterAsync(identity.id, { methods: [] })).rejects.toThrow(
      /short form/,
    )
  })

  test('does not swallow the sync path own diagnostics for an unsupported did:key algorithm', async () => {
    const did = getDID(CODECS.ES256, new Uint8Array(33).fill(1))
    await expect(createTokenEncrypterAsync(did, { methods: [] })).rejects.toThrow(
      /Unsupported DID algorithm for encryption/,
    )
  })
})

describe('deriveSharedSecretAsync()', () => {
  test('agrees with the resolver-backed recipient', async () => {
    const { resolver, profileAgreement } = buildProfile()
    const { sharedSecret, ephemeralPublicKey } = await deriveSharedSecretAsync(kokuinDID, {
      methods: [resolver],
    })
    expect(await profileAgreement.agreeKey(ephemeralPublicKey)).toEqual(sharedSecret)
  })

  test('falls through to the sync path for a self-contained DID', async () => {
    const identity = randomIdentity()
    const { sharedSecret, ephemeralPublicKey } = await deriveSharedSecretAsync(identity.id, {
      methods: [],
    })
    expect(await identity.agreeKey(ephemeralPublicKey)).toEqual(sharedSecret)
  })

  test('names the method when no resolver is registered', async () => {
    await expect(deriveSharedSecretAsync(kokuinDID, { methods: [] })).rejects.toThrow(
      /no resolver registered for did:kokuin/i,
    )
  })

  test('throws when handed something other than a DID string', async () => {
    const notAString = new Uint8Array(32) as unknown as string
    await expect(deriveSharedSecretAsync(notAString, { methods: [] })).rejects.toThrow(/DID string/)
  })
})
