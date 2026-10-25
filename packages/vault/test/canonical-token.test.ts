import { describe, expect, test } from 'vitest'

import { isCanonicalCompactToken } from '../src/canonical-token.js'

describe('isCanonicalCompactToken', () => {
  test('accepts a well-formed three-segment token with no padding', () => {
    expect(isCanonicalCompactToken('aGVsbG8.d29ybGQ.c2ln')).toBe(true)
  })

  test('rejects a token with the wrong segment count', () => {
    expect(isCanonicalCompactToken('aGVsbG8.d29ybGQ')).toBe(false)
    expect(isCanonicalCompactToken('aGVsbG8.d29ybGQ.c2ln.ZXh0cmE')).toBe(false)
  })

  test('rejects padding appended to any segment', () => {
    expect(isCanonicalCompactToken('aGVsbG8=.d29ybGQ.c2ln')).toBe(false)
    expect(isCanonicalCompactToken('aGVsbG8.d29ybGQ=.c2ln')).toBe(false)
    expect(isCanonicalCompactToken('aGVsbG8.d29ybGQ.c2ln=')).toBe(false)
    expect(isCanonicalCompactToken('aGVsbG8.d29ybGQ.c2ln==')).toBe(false)
  })

  test('rejects a segment that fails to decode', () => {
    expect(isCanonicalCompactToken('aGVsbG8.!!!not-base64url!!!.c2ln')).toBe(false)
  })
})
