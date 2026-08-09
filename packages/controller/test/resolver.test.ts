import { describe, expect, test } from 'vitest'

import { createInception, createRotate, decodeKey, didFromInception } from '../src/events.js'
import { createControllerResolver } from '../src/resolver.js'

const seed = new Uint8Array(32).fill(1)

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

describe('createControllerResolver()', () => {
  test('registers for the kokuin method', () => {
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    expect(resolver.method).toBe('kokuin')
  })

  test('resolves the current signing key from the folded log', async () => {
    const { icp, did } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    const resolved = await resolver.resolve(did, {})
    expect(resolved.alg).toBe('EdDSA')
    expect(resolved.publicKey).toEqual(decodeKey(icp.event.k[0]).publicKey)
  })

  test('rejects a DID with no log rather than returning a guess', async () => {
    const { did } = build()
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    await expect(resolver.resolve(did, {})).rejects.toThrow(/Unknown DID/)
  })

  test('rejects a log that does not fold to the requested DID', async () => {
    const { icp } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    await expect(resolver.resolve('did:kokuin:zWRONG', {})).rejects.toThrow()
  })

  test('resolves the rotated key after a rotation, not the original', async () => {
    const { icp, did } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const resolved = await resolver.resolve(did, {})
    expect(resolved.publicKey).toEqual(decodeKey(rot.event.k[0]).publicKey)
    expect(resolved.publicKey).not.toEqual(decodeKey(icp.event.k[0]).publicKey)
  })
})

describe('createControllerResolver().resolveAgreementKey()', () => {
  test('resolves the agreement key set from the folded state', async () => {
    const { icp, did } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    const keys = await resolver.resolveAgreementKey?.(did)
    expect(keys).toHaveLength(1)
    expect(keys?.[0].alg).toBe('X25519')
    expect(keys?.[0].publicKey).toEqual(decodeKey(icp.event.ka[0]).publicKey)
  })

  test('reflects a rotation rather than the inception', async () => {
    const { icp, did } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const keys = await resolver.resolveAgreementKey?.(did)
    expect(keys?.[0].publicKey).toEqual(decodeKey(rot.event.ka[0]).publicKey)
    expect(keys?.[0].publicKey).not.toEqual(decodeKey(icp.event.ka[0]).publicKey)
  })

  test('rejects an unknown DID the same way resolve does', async () => {
    const { did } = build()
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    await expect(resolver.resolveAgreementKey?.(did)).rejects.toThrow(/Unknown DID/)
  })
})
