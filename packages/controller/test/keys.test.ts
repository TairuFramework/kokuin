import { encodeMultibase } from '@kokuin/token'
import { x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { decodeKey, encodeKey, tryDecodeKey } from '../src/keys.js'

describe('tagged key encoding', () => {
  const ed = new Uint8Array(32).fill(7)
  const x = x25519.getPublicKey(new Uint8Array(32).fill(9))

  test('round-trips an Ed25519 key with its algorithm', () => {
    expect(decodeKey(encodeKey(ed, 'EdDSA'))).toEqual({ alg: 'EdDSA', publicKey: ed })
  })

  test('round-trips an X25519 key with its algorithm', () => {
    expect(decodeKey(encodeKey(x, 'X25519'))).toEqual({ alg: 'X25519', publicKey: x })
  })

  test('the same bytes under two algorithms encode differently', () => {
    expect(encodeKey(ed, 'EdDSA')).not.toBe(encodeKey(ed, 'X25519'))
  })

  test('rejects an unknown multicodec rather than guessing by length', () => {
    // 0x99 0x01 is not a codec this package knows. Encoded through token's raw multibase codec,
    // so the unknown prefix survives instead of being wrapped in a known one.
    const unknown = encodeMultibase(new Uint8Array([0x99, 0x01, ...ed]))
    expect(tryDecodeKey(unknown)).toBeUndefined()
    expect(() => decodeKey(unknown)).toThrow(/Unrecognised key encoding/)
  })

  test('rejects a bare untagged key of the right length', () => {
    // What the first implementation wrote: 32 raw bytes, no codec. Accepting these would defeat
    // the tagging, since a future algorithm would be distinguishable only by length.
    expect(tryDecodeKey(encodeMultibase(ed))).toBeUndefined()
  })

  test('tryDecodeKey is total where decodeKey throws', () => {
    expect(tryDecodeKey('not-multibase')).toBeUndefined()
    expect(() => decodeKey('not-multibase')).toThrow()
  })

  test('rejects a bare untagged key whose first two bytes coincide with a codec prefix', () => {
    // 32 raw bytes where the first two happen to be 0xed 0x01 — indistinguishable from a codec
    // prefix by bytes alone. Only the payload length after stripping it (30, not 32) gives it away.
    const collision = encodeMultibase(new Uint8Array([0xed, 0x01, ...new Uint8Array(30).fill(1)]))
    expect(tryDecodeKey(collision)).toBeUndefined()
    expect(() => decodeKey(collision)).toThrow(/Unrecognised key encoding/)
  })

  test('rejects a correctly-tagged key with a truncated payload', () => {
    // A well-formed X25519 prefix over a single-byte payload. Accepting this would mint a DID
    // whose agreement key throws downstream in every future encryptor, instead of failing here.
    const truncated = encodeMultibase(new Uint8Array([0xec, 0x01, 0x00]))
    expect(tryDecodeKey(truncated)).toBeUndefined()
    expect(() => decodeKey(truncated)).toThrow(/Unrecognised key encoding/)
  })
})
