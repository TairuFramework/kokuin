import { createIdentity, randomIdentity } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  factorsFromDescriptors,
  isSecretFactorKind,
  NoAvailableFactor,
  satisfiableFactors,
  VaultTampered,
  wrappableDID,
  wrappingNamesExcludedRecipient,
} from '../src/index.js'

const input = new Uint8Array([1, 2, 3])

describe('factor helpers', () => {
  test('recognises only the supported secret kinds', () => {
    expect(isSecretFactorKind('passphrase')).toBe(true)
    expect(isSecretFactorKind('pin')).toBe(true)
    expect(isSecretFactorKind('did')).toBe(false)
    expect(isSecretFactorKind('unknown')).toBe(false)
  })

  test('reconstructs recipients and supplied secrets without losing costs or order', () => {
    expect(
      factorsFromDescriptors(
        [
          { kind: 'did', params: { recipient: 'did:example:owner' } },
          { kind: 'passphrase', params: { m: 64, t: 2, p: 1 } },
        ],
        { passphrase: input },
      ),
    ).toEqual([
      { kind: 'did', recipientDID: 'did:example:owner' },
      { kind: 'passphrase', input, cost: { m: 64, t: 2, p: 1 } },
    ])
    expect(() => factorsFromDescriptors([{ kind: 'did', params: {} }])).toThrow(VaultTampered)
    expect(() => factorsFromDescriptors([{ kind: 'pin', params: {} }])).toThrow(NoAvailableFactor)
    expect(() => factorsFromDescriptors([{ kind: 'unknown', params: {} }])).toThrow(
      NoAvailableFactor,
    )
  })

  test('compares long and short recipient forms without changing the stored resolution input', async () => {
    const identity = await createIdentity({
      didMethod: 'peer:4',
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const descriptors = [
      { kind: 'did', params: { recipient: identity.longForm } },
      { kind: 'pin', params: {} },
    ]
    expect(wrappableDID(identity)).toBe(identity.longForm)
    const simple = randomIdentity()
    expect(wrappableDID(simple)).toBe(simple.id)
    expect(satisfiableFactors(descriptors, identity)).toEqual(['pin'])
    expect(satisfiableFactors(descriptors, simple)).toBeNull()
    expect(satisfiableFactors(descriptors, null)).toBeNull()
    expect(satisfiableFactors([{ kind: 'unknown', params: {} }], identity)).toBeNull()
    expect(
      wrappingNamesExcludedRecipient(
        { recipientDID: null, factors: descriptors },
        new Set([identity.id]),
      ),
    ).toBe(true)
    expect(
      wrappingNamesExcludedRecipient(
        { recipientDID: simple.id, factors: [] },
        new Set([simple.id]),
      ),
    ).toBe(true)
    expect(
      wrappingNamesExcludedRecipient({ recipientDID: null, factors: descriptors }, new Set()),
    ).toBe(false)
    expect(descriptors[0]?.params.recipient).toBe(identity.longForm)
  })
})
