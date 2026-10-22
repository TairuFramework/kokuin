import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import {
  CODECS,
  type DIDDoc,
  encodeMultibase,
  encodePeer4,
  getDID,
  getPeer4ShortForm,
  signingKeysOf,
} from '../src/index.js'
import { concatBytes } from '../src/utils.js'

function multikey(codec: Uint8Array, publicKey: Uint8Array): string {
  return encodeMultibase(concatBytes(codec, publicKey))
}

const X25519_CODEC = new Uint8Array([0xec, 0x01])

function docWith(
  methods: Array<{ id: string; publicKeyMultibase: string }>,
  extra: Partial<DIDDoc> = {},
): DIDDoc {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: methods.map((method) => ({ ...method, type: 'Multikey' })),
    ...extra,
  } as DIDDoc
}

describe('signingKeysOf', () => {
  const { publicKey } = ed25519.keygen()

  test('a did:key carries exactly its key', () => {
    expect(signingKeysOf(getDID(CODECS.EdDSA, publicKey))).toEqual([{ alg: 'EdDSA', publicKey }])
  })

  test('a short-form did:peer:4 and a did:kokuin carry none', () => {
    const { longForm } = encodePeer4(
      docWith([{ id: '#key-0', publicKeyMultibase: multikey(CODECS.EdDSA, publicKey) }], {
        authentication: ['#key-0'],
      }),
    )
    expect(signingKeysOf(getPeer4ShortForm(longForm))).toBeNull()
    expect(signingKeysOf('did:kokuin:abc')).toBeNull()
  })

  test('a long-form did:peer:4 carries only its authentication keys', () => {
    const agreement = ed25519.keygen().publicKey
    const { longForm } = encodePeer4(
      docWith(
        [
          { id: '#key-0', publicKeyMultibase: multikey(CODECS.EdDSA, publicKey) },
          { id: '#key-1', publicKeyMultibase: multikey(X25519_CODEC, agreement) },
        ],
        { authentication: ['#key-0'], keyAgreement: ['#key-1'] },
      ),
    )
    expect(signingKeysOf(longForm)).toEqual([{ alg: 'EdDSA', publicKey }])
  })

  test('an unreadable authentication entry does not hide a readable one', () => {
    const { longForm } = encodePeer4(
      docWith(
        [
          { id: '#key-0', publicKeyMultibase: 'z6MkAbc' },
          { id: '#key-1', publicKeyMultibase: multikey(CODECS.EdDSA, publicKey) },
        ],
        { authentication: ['#key-0', '#key-1'] },
      ),
    )
    expect(signingKeysOf(longForm)).toEqual([{ alg: 'EdDSA', publicKey }])
  })

  test('an oversized authentication entry is skipped', () => {
    const { longForm } = encodePeer4(
      docWith([{ id: '#key-0', publicKeyMultibase: `z${'1'.repeat(200)}` }], {
        authentication: ['#key-0'],
      }),
    )
    expect(signingKeysOf(longForm)).toEqual([])
  })

  test('a did:key that does not decode throws', () => {
    expect(() => signingKeysOf('did:key:z6Mk')).toThrow()
  })
})
