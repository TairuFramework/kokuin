import { describe, expect, test } from 'vitest'

import { deriveCodeChallenge, generateCodeVerifier, generateState } from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

describe('generateCodeVerifier()', () => {
  test('returns a 43-char url-safe base64url string', () => {
    const verifier = generateCodeVerifier(fakeRuntime())
    expect(verifier).toHaveLength(43)
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})

describe('deriveCodeChallenge()', () => {
  test('matches the RFC 7636 Appendix B S256 vector', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    expect(deriveCodeChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
  })
})

describe('generateState()', () => {
  test('returns a url-safe base64url string', () => {
    const state = generateState(fakeRuntime())
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(state.length).toBeGreaterThan(0)
  })
})
