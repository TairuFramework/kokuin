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

  test('encodes an empty object', () => {
    expect(decoder.decode(canonicalBytes({}))).toBe('{}')
  })

  test('encodes an empty array', () => {
    expect(decoder.decode(canonicalBytes({ a: [] }))).toBe('{"a":[]}')
  })

  test('nests objects inside arrays', () => {
    expect(decoder.decode(canonicalBytes([{ b: 2, a: 1 }]))).toBe('[{"a":1,"b":2}]')
  })

  test('preserves unicode strings in raw UTF-8 form without escaping', () => {
    const utf8 = canonicalBytes({ emoji: '🔑', greek: 'Ω' })
    const decoded = decoder.decode(utf8)
    expect(decoded).toBe('{"emoji":"🔑","greek":"Ω"}')
  })

  test('sorts numeric-looking keys lexicographically, not numerically', () => {
    // "10" comes before "9" in lexicographic order
    expect(decoder.decode(canonicalBytes({ '9': 'a', '10': 'b' }))).toBe('{"10":"b","9":"a"}')
  })

  test('sorts non-ASCII keys lexicographically', () => {
    const obj: Record<string, number> = {}
    obj['ß'] = 1
    obj['ä'] = 2
    expect(decoder.decode(canonicalBytes(obj))).toBe('{"ß":1,"ä":2}')
  })

  test('rejects Date objects instead of encoding them as empty objects', () => {
    expect(() => canonicalBytes({ a: new Date() })).toThrow(/plain objects/)
  })

  test('rejects Map objects instead of encoding them as empty objects', () => {
    expect(() => canonicalBytes({ a: new Map() })).toThrow(/plain objects/)
  })

  test('rejects Uint8Array instead of encoding numeric keys', () => {
    expect(() => canonicalBytes({ a: new Uint8Array([1, 2, 3]) })).toThrow(/plain objects/)
  })

  test('throws on undefined values in arrays rather than encoding as null', () => {
    expect(() => canonicalBytes({ a: [1, undefined, 2] })).toThrow(/unsupported/)
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
