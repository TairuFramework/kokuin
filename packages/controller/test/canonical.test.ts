import { describe, expect, test } from 'vitest'

import { canonicalBytes, digestOf, verifyDigest } from '../src/canonical.js'

const decoder = new TextDecoder()

describe('canonicalBytes()', () => {
  test('sorts object keys and emits no whitespace', () => {
    expect(decoder.decode(canonicalBytes({ b: 1, a: 2 }))).toBe('{"a":2,"b":1}')
  })

  test('sorts nested object keys', () => {
    expect(decoder.decode(canonicalBytes({ z: { y: 1, x: 2 } }))).toBe('{"z":{"x":2,"y":1}}')
  })

  test('preserves array order', () => {
    expect(decoder.decode(canonicalBytes({ a: ['c', 'b'] }))).toBe('{"a":["c","b"]}')
  })

  test('drops undefined properties so optional fields are absent, not null', () => {
    expect(decoder.decode(canonicalBytes({ a: 1, b: undefined }))).toBe('{"a":1}')
  })

  test('key order does not change the bytes', () => {
    expect(canonicalBytes({ a: 1, b: 2 })).toEqual(canonicalBytes({ b: 2, a: 1 }))
  })

  test('rejects a non-finite number — it would not round-trip', () => {
    expect(() => canonicalBytes({ a: Number.NaN })).toThrow(/finite/)
  })
})

describe('digestOf()', () => {
  test('is stable across key order', () => {
    expect(digestOf({ a: 1, b: 2 })).toBe(digestOf({ b: 2, a: 1 }))
  })

  test('differs for different content', () => {
    expect(digestOf({ a: 1 })).not.toBe(digestOf({ a: 2 }))
  })

  test('is a base58btc multibase string', () => {
    expect(digestOf({ a: 1 })).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/)
  })
})

describe('verifyDigest()', () => {
  test('accepts a matching value', () => {
    expect(verifyDigest(digestOf({ a: 1 }), { a: 1 })).toBe(true)
  })

  test('rejects a mismatched value', () => {
    expect(verifyDigest(digestOf({ a: 1 }), { a: 2 })).toBe(false)
  })

  test('rejects a malformed digest instead of throwing', () => {
    expect(verifyDigest('not-multibase', { a: 1 })).toBe(false)
  })
})
