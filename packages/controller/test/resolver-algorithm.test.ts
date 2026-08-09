import { describe, expect, test, vi } from 'vitest'

// `resolve` reads the algorithm off the decoded signing key rather than hardcoding 'EdDSA'
// (resolver.ts:44-47). `KeyAlgorithm` is a closed two-member union and the encoder rejects
// anything outside it, so a hand-built event carrying a differently-tagged algorithm is not
// constructible through the public API — the only way to observe the passthrough is to force
// `decodeKey` itself to return something other than 'EdDSA'. This lives in its own file, rather
// than alongside `resolver.test.ts`, because `vi.mock` replaces the module for every test in the
// file it appears in, and the other resolver tests rely on `decodeKey` behaving for real.
vi.mock('../src/keys.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/keys.js')>()
  return { ...actual, decodeKey: vi.fn(actual.decodeKey) }
})

const keys = await import('../src/keys.js')
const { createInception, didFromInception } = await import('../src/events.js')
const { createControllerResolver } = await import('../src/resolver.js')

const seed = new Uint8Array(32).fill(1)

describe('createControllerResolver().resolve() algorithm passthrough', () => {
  test('surfaces whatever algorithm the decoded key carries, not a hardcoded EdDSA', async () => {
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const resolver = createControllerResolver({ loadLog: async () => [icp] })

    const mockedDecodeKey = vi.mocked(keys.decodeKey)
    mockedDecodeKey.mockReturnValueOnce({
      // Not a real member of `KeyAlgorithm` — the point is that `resolve` must surface exactly
      // what `decodeKey` returns rather than a literal 'EdDSA', so any value that is neither
      // 'EdDSA' nor 'X25519' (which would throw) proves the passthrough.
      alg: 'Ed448' as unknown as 'EdDSA',
      publicKey: new Uint8Array(32).fill(7),
    })

    const resolved = await resolver.resolve(did, {})
    expect(resolved.alg).toBe('Ed448')
    expect(resolved.publicKey).toEqual(new Uint8Array(32).fill(7))
  })
})
