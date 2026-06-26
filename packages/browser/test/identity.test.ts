import { beforeAll, describe, expect, test, vi } from 'vitest'

// Use vi.hoisted so the mock fn is available inside the hoisted vi.mock factory
const { mockGetAsync, mockProvideAsync } = vi.hoisted(() => ({
  mockGetAsync: vi.fn(),
  mockProvideAsync: vi.fn(),
}))

let testKeyPair: CryptoKeyPair

vi.mock('../src/store.js', () => ({
  BrowserKeyStore: {
    open: vi.fn().mockResolvedValue({
      entry: vi.fn().mockReturnValue({
        getAsync: mockGetAsync,
        provideAsync: mockProvideAsync,
      }),
    }),
  },
}))

import { provideSigningIdentity } from '../src/identity.js'

beforeAll(async () => {
  testKeyPair = (await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  )) as CryptoKeyPair
  mockProvideAsync.mockResolvedValue(testKeyPair)
})

describe('provideSigningIdentity()', () => {
  test('returns identity with valid DID', async () => {
    const identity = await provideSigningIdentity('test-key')
    expect(identity.id).toMatch(/^did:key:z/)
  })

  test('returns identity with signToken function', async () => {
    const identity = await provideSigningIdentity('test-key')
    expect(identity.signToken).toBeInstanceOf(Function)
  })

  test('signs token with ES256 algorithm', async () => {
    const identity = await provideSigningIdentity('test-key')
    const token = await identity.signToken({ test: true })
    expect(token.header.alg).toBe('ES256')
    expect(token.header.typ).toBe('JWT')
  })

  test('signed token includes issuer matching identity', async () => {
    const identity = await provideSigningIdentity('test-key')
    const token = await identity.signToken({ foo: 'bar' })
    expect(token.payload.iss).toBe(identity.id)
    expect(token.payload.foo).toBe('bar')
  })

  test('signed token has valid JWT structure', async () => {
    const identity = await provideSigningIdentity('test-key')
    const token = await identity.signToken({ x: 1 })
    expect(token.data).toContain('.')
    expect(token.signature).toBeDefined()
    expect(token.signature.length).toBeGreaterThan(0)
  })

  test('rejects payload with mismatched issuer', async () => {
    const identity = await provideSigningIdentity('test-key')
    await expect(identity.signToken({ iss: 'did:key:wrong' })).rejects.toThrow('Invalid payload')
  })

  test('accepts payload with matching issuer', async () => {
    const identity = await provideSigningIdentity('test-key')
    const token = await identity.signToken({ iss: identity.id })
    expect(token.payload.iss).toBe(identity.id)
  })

  test('accepts string store parameter', async () => {
    const identity = await provideSigningIdentity('test-key', 'custom-db')
    expect(identity.id).toMatch(/^did:key:z/)
  })

  test('signatures are always low-S (50 iterations, round-trip verifyToken)', async () => {
    // Regression test: Web Crypto P-256 emits high-S ~50% of the time.
    // normalizeSignatureToLowS() must flip high-S values; verifyToken enforces
    // { lowS: true } and will reject any un-normalized signature. Running 50
    // iterations makes a silent normalization failure fail with probability
    // 1 - (0.5)^50 ≈ 1 - 8.9e-16.
    const { verifyToken } = await import('@kokuin/token')
    const identity = await provideSigningIdentity('test-key')
    for (let i = 0; i < 50; i++) {
      const token = await identity.signToken({ iter: i })
      await expect(verifyToken(token)).resolves.toBeDefined()
    }
  }, 30_000)
})
