import {
  createSigningIdentityForDID,
  type DIDMethodResolver,
  type DIDString,
  randomIdentity,
  randomPrivateKey,
  type SigningIdentity,
  stringifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { checkCapability, checkDelegationChain } from '../src/index.js'

// A DID whose keys cannot be recovered from the identifier — the shape `did:kokuin:` has. The
// resolver here is a hand-built fake: this package must not depend on `@kokuin/controller`, and a
// real folded log would prove nothing extra about the option threading.
const profileDID = 'did:kokuin:zTestProfile' as DIDString

function buildProfile(): { identity: SigningIdentity; resolver: DIDMethodResolver } {
  const identity = createSigningIdentityForDID(profileDID, randomPrivateKey())
  const resolver: DIDMethodResolver = {
    method: 'kokuin',
    resolve: async (did: string) => {
      if (did !== profileDID) {
        throw new Error(`Unknown DID: ${did}`)
      }
      return { alg: 'EdDSA', publicKey: identity.publicKey }
    },
    // A fake with one fixed key, so the two questions genuinely coincide — the alias
    // `DIDMethodResolver.resolveHistoric` documents for a method whose key set never changes. It
    // has to be published all the same: `checkCapability` verifies archived material and asks for
    // it, and its absence is refused rather than answered from `resolve`.
    resolveHistoric: async (did: string) => {
      if (did !== profileDID) {
        throw new Error(`Unknown DID: ${did}`)
      }
      return { alg: 'EdDSA', publicKey: identity.publicKey }
    },
  }
  return { identity, resolver }
}

describe('DelegationChainOptions.methods', () => {
  test('checkCapability resolves a leaf capability issued by a registry-only DID', async () => {
    // One hop, so the only capability verified is the head — inside `checkCapability` itself.
    // The tail is empty, so `checkDelegationChain` never verifies anything here.
    const { identity: root, resolver } = buildProfile()
    const device = randomIdentity()

    const rootToDevice = await root.signToken({
      sub: profileDID,
      aud: device.id,
      act: 'foo',
      res: 'bar',
    })
    const leaf = await device.signToken({
      sub: profileDID,
      prc: 'foo',
      cap: [stringifyToken(rootToDevice)],
    })

    await expect(
      checkCapability({ act: 'foo', res: 'bar' }, leaf.payload, { methods: [resolver] }),
    ).resolves.toBeUndefined()

    // Without the registry the chain cannot be walked at all.
    await expect(checkCapability({ act: 'foo', res: 'bar' }, leaf.payload)).rejects.toThrow(
      `Unknown DID: ${profileDID}`,
    )
  })

  test('checkDelegationChain resolves a registry-only DID deeper in the chain', async () => {
    // Called directly, so the capability it verifies is unambiguously the one inside
    // `checkDelegationChain`.
    const { identity: root, resolver } = buildProfile()
    const manager = randomIdentity()
    const device = randomIdentity()

    const rootToManager = await root.signToken({
      sub: profileDID,
      aud: manager.id,
      act: 'foo',
      res: 'bar',
    })
    const managerToDevice = await manager.signToken({
      sub: profileDID,
      aud: device.id,
      act: 'foo',
      res: 'bar',
    })

    await expect(
      checkDelegationChain(managerToDevice.payload, [stringifyToken(rootToManager)], {
        methods: [resolver],
      }),
    ).resolves.toBeUndefined()

    await expect(
      checkDelegationChain(managerToDevice.payload, [stringifyToken(rootToManager)]),
    ).rejects.toThrow(`Unknown DID: ${profileDID}`)
  })

  test('checkCapability forwards the registry to every link, not just the leaf', async () => {
    // Two hops with the registry-only DID at the *root*: the leaf capability the head of
    // `checkCapability` verifies is a plain did:key, so only the recursion into
    // `checkDelegationChain` needs the registry.
    const { identity: root, resolver } = buildProfile()
    const manager = randomIdentity()
    const device = randomIdentity()

    const rootToManager = await root.signToken({
      sub: profileDID,
      aud: manager.id,
      act: 'foo',
      res: 'bar',
    })
    const managerToDevice = await manager.signToken({
      sub: profileDID,
      aud: device.id,
      act: 'foo',
      res: 'bar',
    })
    const leaf = await device.signToken({
      sub: profileDID,
      prc: 'foo',
      cap: [stringifyToken(managerToDevice), stringifyToken(rootToManager)],
    })

    await expect(
      checkCapability({ act: 'foo', res: 'bar' }, leaf.payload, { methods: [resolver] }),
    ).resolves.toBeUndefined()

    await expect(checkCapability({ act: 'foo', res: 'bar' }, leaf.payload)).rejects.toThrow(
      `Unknown DID: ${profileDID}`,
    )
  })
})
