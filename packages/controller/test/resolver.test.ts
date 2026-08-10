import { describe, expect, test } from 'vitest'

import {
  createInception,
  createRevoke,
  createRotate,
  decodeKey,
  didFromInception,
} from '../src/events.js'
import { createControllerResolver } from '../src/resolver.js'

const seed = new Uint8Array(32).fill(1)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
// Not the controller's seed: the revoke below is signed by a delegate, so only the capability it
// carries can authorise it.
const delegateSeed = new Uint8Array(32).fill(3)
const cap = 'eyJ.delegated.revoke'

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

/** A log whose last event is a capability-authorised revoke — foldable only asynchronously. */
function capLog() {
  const { icp, did } = build()
  const rev = createRevoke(delegateSeed, 0, did, icp.event, device, { gen: 0, seq: 0 }, { cap })
  return { icp, did, log: [icp, rev] }
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

describe('createControllerResolver() with a capability-authorised revoke', () => {
  test('rejects the log when no verifier is configured', async () => {
    const { did, log } = capLog()
    const resolver = createControllerResolver({ loadLog: async () => log })
    await expect(resolver.resolve(did, {})).rejects.toThrow(/capability/)
  })

  test('resolves it when the configured verifier authorises the capability', async () => {
    const { icp, did, log } = capLog()
    const seen: Array<Array<string>> = []
    const resolver = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async (capability, subject, target) => {
        seen.push([capability, subject, target])
        return true
      },
    })

    const resolved = await resolver.resolve(did, {})
    // The revoke establishes no key, so the inception's is still current.
    expect(resolved.publicKey).toEqual(decodeKey(icp.event.k[0]).publicKey)
    // The verifier is handed the capability, the controller it must name as `sub`, and the DID
    // being denied — passing anything else would authorise a revoke of the wrong device.
    expect(seen).toEqual([[cap, did, device]])
  })

  test('rejects it when the configured verifier declines the capability', async () => {
    const { did, log } = capLog()
    const resolver = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async () => false,
    })
    await expect(resolver.resolve(did, {})).rejects.toThrow(
      /capability does not authorise this revoke/,
    )
  })

  test('applies the verifier to resolveAgreementKey too, not only to resolve', async () => {
    const { icp, did, log } = capLog()
    const declining = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async () => false,
    })
    await expect(declining.resolveAgreementKey?.(did)).rejects.toThrow(/capability/)

    const accepting = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async () => true,
    })
    const keys = await accepting.resolveAgreementKey?.(did)
    // A revoke carries the agreement set forward, so it is still the inception's.
    expect(keys?.[0].publicKey).toEqual(decodeKey(icp.event.ka[0]).publicKey)
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
