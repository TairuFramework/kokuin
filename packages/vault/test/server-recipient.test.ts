import {
  createFullIdentity,
  createIdentity,
  createSigningIdentity,
  isKeyAgreementIdentity,
  type KeyAgreementIdentity,
  randomIdentity,
  type SigningIdentity,
} from '@kokuin/token'
import { createRuntime } from '@sozai/runtime'
import { describe, expect, test } from 'vitest'

import { NoAvailableFactor } from '../src/errors.js'
import { getSuite, SUITE_VAULT_1 } from '../src/suite.js'

const runtime = createRuntime()
const suite = getSuite(SUITE_VAULT_1)

const wrappingID = 'w-server-recipient'
const keyID = 'k-server-recipient'
const keyVersion = 1

async function roundTrip(recipientDID: string, identity: KeyAgreementIdentity): Promise<void> {
  const contentKey = suite.generateContentKey(runtime)
  const { descriptors, iv, wrappedKey } = await suite.wrap({
    runtime,
    contentKey,
    factors: [{ kind: 'did', recipientDID }],
    wrappingID,
    keyID,
    keyVersion,
  })
  const opened = await suite.unwrap({
    identity,
    descriptors,
    iv,
    wrappedKey,
    wrappingID,
    keyID,
    keyVersion,
  })
  expect(opened).toEqual(contentKey)
}

describe('an engine identity as a wrapping recipient', () => {
  test('randomIdentity, what an engine with no configured key gets', async () => {
    const identity = randomIdentity()
    expect(isKeyAgreementIdentity(identity)).toBe(true)
    await roundTrip(identity.id, identity)
  })

  test('createFullIdentity from a configured private key', async () => {
    const identity = createFullIdentity(randomIdentity().privateKey)
    expect(isKeyAgreementIdentity(identity)).toBe(true)
    await roundTrip(identity.id, identity)
  })
})

describe('when the engine identity cannot decrypt', () => {
  test('a signing-only identity is refused rather than opening the wrapping', async () => {
    const signing: SigningIdentity = createSigningIdentity(randomIdentity().privateKey)
    expect(isKeyAgreementIdentity(signing)).toBe(false)

    const contentKey = suite.generateContentKey(runtime)
    const { descriptors, iv, wrappedKey } = await suite.wrap({
      runtime,
      contentKey,
      factors: [{ kind: 'did', recipientDID: signing.id }],
      wrappingID,
      keyID,
      keyVersion,
    })

    await expect(
      suite.unwrap({
        identity: null,
        descriptors,
        iv,
        wrappedKey,
        wrappingID,
        keyID,
        keyVersion,
      }),
    ).rejects.toThrow(NoAvailableFactor)
  })
})

describe('addressing the engine as a recipient', () => {
  test('a peer:4 engine is unaddressable through the identity surface a plugin holds', async () => {
    const peer4 = await createIdentity({
      didMethod: 'peer:4',
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const asPlugin: SigningIdentity = peer4
    expect(asPlugin.id).toBe(peer4.id)
    expect('longForm' in asPlugin).toBe(true)

    await expect(roundTrip(asPlugin.id, peer4)).rejects.toThrow(/short form/i)
    await roundTrip(peer4.longForm, peer4)
  })
})
