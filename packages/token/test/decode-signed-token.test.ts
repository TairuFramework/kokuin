import { describe, expect, test } from 'vitest'

import { randomIdentity } from '../src/identity.js'
import { decodeSignedToken, stringifyToken } from '../src/index.js'

describe('decodeSignedToken()', () => {
  test('decodes a signed token without losing the signed bytes', async () => {
    const signed = await randomIdentity().signToken({ sub: 'x' })
    const [header, payload] = stringifyToken(signed).split('.')
    const decoded = decodeSignedToken(stringifyToken(signed))
    expect(decoded).toEqual({
      data: `${header}.${payload}`,
      header: signed.header,
      payload: signed.payload,
      signature: signed.signature,
    })
  })

  test('does not verify the signature', async () => {
    const signed = await randomIdentity().signToken({ sub: 'x' })
    const str = stringifyToken(signed)
    const last = str.slice(-1)
    const tampered = `${str.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`
    expect(decodeSignedToken(tampered).payload).toEqual(signed.payload)
  })

  test.each(['a.b', 'a.b.', 'not-a-token'])('throws for %s', (input) => {
    expect(() => decodeSignedToken(input)).toThrow(
      'Invalid token format: expected 3 parts separated by dots',
    )
  })
})
