import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import {
  CODECS,
  getAlgorithmAndPublicKey,
  getDID,
  getSignatureInfo,
  resolveIssuerWithDoc,
} from '../src/did.js'
import { encodeMultibase } from '../src/multibase.js'
import { encodePeer4 } from '../src/peer4.js'

describe('getAlgorithmAndPublicKey()', () => {
  test('returns null for bytes shorter than any codec', () => {
    const shortBytes = new Uint8Array([0xed])
    expect(getAlgorithmAndPublicKey(shortBytes)).toBeNull()
  })

  test('returns null for empty bytes', () => {
    const empty = new Uint8Array(0)
    expect(getAlgorithmAndPublicKey(empty)).toBeNull()
  })

  test('returns algorithm and public key for valid EdDSA bytes', () => {
    const publicKey = new Uint8Array([1, 2, 3, 4])
    const codec = CODECS.EdDSA
    const bytes = new Uint8Array(codec.length + publicKey.length)
    bytes.set(codec)
    bytes.set(publicKey, codec.length)
    const result = getAlgorithmAndPublicKey(bytes)
    expect(result).not.toBeNull()
    expect(result?.[0]).toBe('EdDSA')
    expect(result?.[1]).toEqual(publicKey)
  })

  test('returns algorithm and public key for valid ES256 bytes', () => {
    const publicKey = new Uint8Array([5, 6, 7, 8])
    const codec = CODECS.ES256
    const bytes = new Uint8Array(codec.length + publicKey.length)
    bytes.set(codec)
    bytes.set(publicKey, codec.length)
    const result = getAlgorithmAndPublicKey(bytes)
    expect(result).not.toBeNull()
    expect(result?.[0]).toBe('ES256')
    expect(result?.[1]).toEqual(publicKey)
  })
})

describe('getSignatureInfo()', () => {
  test('throws for invalid DID prefix', () => {
    expect(() => getSignatureInfo('invalid:key:z123')).toThrow('Invalid DID format')
  })

  test('throws for unsupported codec', () => {
    expect(() => getSignatureInfo('did:key:z1111')).toThrow('Unsupported DID signature codec')
  })

  test('throws for EdDSA key with wrong size', () => {
    const codec = CODECS.EdDSA
    const shortKey = new Uint8Array(16)
    const did = getDID(codec, shortKey)
    expect(() => getSignatureInfo(did)).toThrow('Invalid public key size')
  })

  test('throws for ES256 key with wrong size', () => {
    const codec = CODECS.ES256
    const wrongKey = new Uint8Array(32)
    const did = getDID(codec, wrongKey)
    expect(() => getSignatureInfo(did)).toThrow('Invalid public key size')
  })

  test('accepts EdDSA key with correct size (32 bytes)', () => {
    const codec = CODECS.EdDSA
    const key = new Uint8Array(32).fill(1)
    const did = getDID(codec, key)
    const [alg, extractedKey] = getSignatureInfo(did)
    expect(alg).toBe('EdDSA')
    expect(extractedKey.length).toBe(32)
  })

  test('accepts ES256 key with correct size (33 bytes)', () => {
    const codec = CODECS.ES256
    const key = new Uint8Array(33).fill(2)
    const did = getDID(codec, key)
    const [alg, extractedKey] = getSignatureInfo(did)
    expect(alg).toBe('ES256')
    expect(extractedKey.length).toBe(33)
  })

  test('rejects an over-long did:key before decoding', () => {
    const did = `did:key:z${'0'.repeat(5_000_000)}`
    expect(() => getSignatureInfo(did)).toThrow('Invalid DID format: key too large')
  })

  test('accepts a maximum-size legitimate did:key', () => {
    // ES256 is the largest supported: 2-byte codec + 33-byte key = 48 base58 chars.
    const publicKey = new Uint8Array(33).fill(0xff)
    const did = getDID(CODECS.ES256, publicKey)
    expect(did.length - 'did:key:z'.length).toBe(48)
    expect(() => getSignatureInfo(did)).not.toThrow()
  })
})

describe('getDID()', () => {
  test('creates a DID string with did:key:z prefix', () => {
    const codec = CODECS.EdDSA
    const publicKey = new Uint8Array([1, 2, 3])
    const did = getDID(codec, publicKey)
    expect(did.startsWith('did:key:z')).toBe(true)
  })

  test('round-trips through getSignatureInfo', () => {
    const codec = CODECS.EdDSA
    const publicKey = new Uint8Array(32).fill(42)
    const did = getDID(codec, publicKey)
    const [alg, extractedKey] = getSignatureInfo(did)
    expect(alg).toBe('EdDSA')
    expect(extractedKey).toEqual(publicKey)
  })
})

describe('resolveIssuerWithDoc() resolver doc bound', () => {
  test('rejects an oversized resolver doc before the base58 encode', async () => {
    // A structurally valid doc whose canonical JSON exceeds the 4 KiB default.
    const bigDoc = {
      verificationMethod: [
        {
          id: '#key-1',
          type: 'Multikey',
          // publicKeyMultibase far larger than any real key.
          publicKeyMultibase: `z${'1'.repeat(8 * 1024)}`,
        },
      ],
      authentication: ['#key-1'],
    }
    const shortForm = 'did:peer:4zQmNotTheMatchingHash'
    const resolver = async () => bigDoc as never
    await expect(resolveIssuerWithDoc(shortForm, {}, resolver)).rejects.toThrow(
      'did:peer:4 resolver doc too large',
    )
  })

  test('a legitimate resolver doc still resolves', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { doc, shortForm } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    const resolver = async () => doc
    await expect(resolveIssuerWithDoc(shortForm, {}, resolver)).resolves.toBeDefined()
  })
})
