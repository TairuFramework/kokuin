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
})
