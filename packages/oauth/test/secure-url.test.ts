import { describe, expect, test } from 'vitest'

import { assertSecureURL } from '../src/secure-url.js'

describe('assertSecureURL()', () => {
  test.each([
    'https://example.com/token',
    'http://localhost:8080/token',
    'http://LOCALHOST/token',
    'http://127.0.0.1/token',
    'http://127.1.2.3:9000/token',
    'http://[::1]:9000/token',
  ])('accepts %s', (url) => {
    expect(() => assertSecureURL(url)).not.toThrow()
  })

  test.each(['http://example.com/token', 'http://foo.localhost/token', 'http://128.0.0.1/token'])(
    'refuses %s',
    (url) => {
      expect(() => assertSecureURL(url)).toThrow(/https/i)
    },
  )
})
