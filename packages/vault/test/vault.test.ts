import { deriveSharedSecretAsync } from '@kokuin/jwe'
import { createIdentity, randomIdentity } from '@kokuin/token'
import type * as Aes from '@noble/ciphers/aes.js'
import { gcm } from '@noble/ciphers/aes.js'
import { fromB64 } from '@sozai/codec'
import { createRuntime } from '@sozai/runtime'
import { describe, expect, test, vi } from 'vitest'

import type { FactorDescriptor, FactorInput, WrappedKey } from '../src/index.js'
import {
  checkDescriptorDigest,
  descriptorDigest,
  getSuite,
  InvalidVaultFactors,
  NoAvailableFactor,
  SUITE_VAULT_1,
  VaultSecretRejected,
  VaultTampered,
  wrappableDID,
} from '../src/index.js'

vi.mock('@noble/ciphers/aes.js', async (importOriginal) => {
  const actual = await importOriginal<typeof Aes>()
  return { ...actual, gcm: vi.fn(actual.gcm) }
})

const runtime = createRuntime()
const suite = getSuite(SUITE_VAULT_1)
const address = { keyID: 'content-key', keyVersion: 1, wrappingID: 'device-wrapping' }
const plaintext = new TextEncoder().encode('opaque host state')
const passphrase = new TextEncoder().encode('correct horse battery staple')
const pin = new TextEncoder().encode('4829')
const cost = { m: 8, t: 1, p: 1 }

function openParams(wrapped: WrappedKey) {
  return { ...address, ...wrapped, expectedDescriptorDigest: wrapped.descriptorDigest }
}

async function multifactor() {
  const identity = randomIdentity()
  const contentKey = suite.generateContentKey(runtime)
  const wrapped = await suite.wrap({
    ...address,
    runtime,
    contentKey,
    factors: [
      { kind: 'did', recipientDID: identity.id },
      { kind: 'passphrase', input: passphrase, cost },
      { kind: 'pin', input: pin, cost },
    ],
  })
  return { identity, contentKey, wrapped }
}

describe('vault crypto', () => {
  test('rotation replaces the content key and carries plaintext to the next version', async () => {
    const identity = randomIdentity()
    const firstKey = suite.generateContentKey(runtime)
    const nextKey = suite.generateContentKey(runtime)
    expect(firstKey).toHaveLength(32)
    expect(nextKey).not.toEqual(firstKey)
    const entryID = 'current-state'
    const first = suite.encryptEntry({
      ...address,
      runtime,
      contentKey: firstKey,
      entryID,
      plaintext,
    })
    const recovered = suite.decryptEntry({ ...address, ...first, contentKey: firstKey, entryID })
    const nextAddress = { ...address, keyVersion: 2 }
    const next = suite.encryptEntry({
      ...nextAddress,
      runtime,
      contentKey: nextKey,
      entryID,
      plaintext: recovered,
    })
    const wrapped = await suite.wrap({
      ...nextAddress,
      runtime,
      contentKey: nextKey,
      factors: [{ kind: 'did', recipientDID: identity.id }],
    })
    const opened = await suite.unwrap({
      ...openParams(wrapped),
      ...nextAddress,
      identity,
    })
    expect(suite.decryptEntry({ ...nextAddress, ...next, contentKey: opened, entryID })).toEqual(
      plaintext,
    )
    expect(() =>
      suite.decryptEntry({ ...nextAddress, ...next, contentKey: firstKey, entryID }),
    ).toThrow(VaultTampered)
    expect(() =>
      suite.decryptEntry({ ...nextAddress, ...first, contentKey: firstKey, entryID }),
    ).toThrow(VaultTampered)
    await expect(suite.unwrap({ ...openParams(wrapped), identity })).rejects.toThrow()
  })

  test('opens did, passphrase and pin in their authenticated order', async () => {
    const { identity, contentKey, wrapped } = await multifactor()
    expect(wrapped.descriptors.map((factor) => factor.kind)).toEqual(['did', 'passphrase', 'pin'])
    expect(wrapped.descriptorDigest).toBe(descriptorDigest(wrapped.descriptors))
    expect(
      await suite.unwrap({
        ...openParams(wrapped),
        identity,
        inputs: { passphrase, pin },
      }),
    ).toEqual(contentKey)
    await expect(
      suite.unwrap({
        ...openParams(wrapped),
        identity,
        inputs: { passphrase },
      }),
    ).rejects.toThrow(NoAvailableFactor)
    await expect(
      suite.unwrap({
        ...openParams(wrapped),
        identity: null,
        inputs: { passphrase, pin },
      }),
    ).rejects.toThrow(NoAvailableFactor)
  })

  test('refuses reordered descriptors before agreement or GCM', async () => {
    const { identity, wrapped } = await multifactor()
    const descriptors = [...wrapped.descriptors].reverse()
    const agreeKey = vi.fn(identity.agreeKey)
    vi.mocked(gcm).mockClear()
    expect(() =>
      checkDescriptorDigest({
        descriptors,
        expectedDescriptorDigest: wrapped.descriptorDigest,
      }),
    ).toThrow(VaultTampered)
    await expect(
      suite.unwrap({
        ...openParams(wrapped),
        descriptors,
        identity: { id: identity.id, agreeKey },
        inputs: { passphrase, pin },
      }),
    ).rejects.toThrow(VaultTampered)
    expect(agreeKey).not.toHaveBeenCalled()
    expect(gcm).not.toHaveBeenCalled()
  })

  test.each(['passphrase', 'pin'] as const)('a wrong %s retains the GCM failure', async (kind) => {
    const { identity, wrapped } = await multifactor()
    vi.mocked(gcm).mockClear()
    const error: unknown = await suite
      .unwrap({
        ...openParams(wrapped),
        identity,
        inputs: { passphrase, pin, [kind]: new TextEncoder().encode('incorrect') },
      })
      .catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(VaultSecretRejected)
    expect(error).not.toBeInstanceOf(VaultTampered)
    if (!(error instanceof VaultSecretRejected)) throw new Error('expected secret rejection')
    expect(error.cause).toBeInstanceOf(Error)
    expect(gcm).toHaveBeenCalledTimes(1)
  })

  test.each(['recipient', 'm', 'salt'])(
    'editing descriptor %s is tampering before agreement or GCM',
    async (field) => {
      const { identity, wrapped } = await multifactor()
      const descriptors: Array<FactorDescriptor> = wrapped.descriptors.map((descriptor) => ({
        ...descriptor,
        params: { ...descriptor.params },
      }))
      const target = descriptors.find(
        (descriptor) => descriptor.kind === (field === 'recipient' ? 'did' : 'passphrase'),
      )
      if (target === undefined) throw new Error('missing factor')
      target.params[field] = field === 'm' ? 16 : 'altered'
      const agreeKey = vi.fn(identity.agreeKey)
      vi.mocked(gcm).mockClear()
      await expect(
        suite.unwrap({
          ...openParams(wrapped),
          descriptors,
          descriptorDigest: descriptorDigest(descriptors),
          identity: { id: identity.id, agreeKey },
          inputs: { passphrase, pin },
        }),
      ).rejects.toThrow(VaultTampered)
      expect(agreeKey).not.toHaveBeenCalled()
      expect(gcm).not.toHaveBeenCalled()
    },
  )

  test.each(['key', 'peer:4'] as const)('wraps to a did:%s recipient', async (didMethod) => {
    const identity = await createIdentity({
      didMethod,
      keys:
        didMethod === 'key'
          ? [{ purpose: 'sig', alg: 'EdDSA' }]
          : [
              { purpose: 'sig', alg: 'EdDSA' },
              { purpose: 'kem', alg: 'X25519' },
            ],
    })
    const recipientDID = wrappableDID(identity)
    const contentKey = suite.generateContentKey(runtime)
    const wrapped = await suite.wrap({
      ...address,
      runtime,
      contentKey,
      factors: [{ kind: 'did', recipientDID }],
    })
    expect(await suite.unwrap({ ...openParams(wrapped), identity })).toEqual(contentKey)
    const epk = wrapped.descriptors[0]?.params.epk
    if (typeof epk !== 'string') throw new Error('missing ephemeral public key')
    expect(await identity.agreeKey(fromB64(epk))).toHaveLength(32)
    const shared = await deriveSharedSecretAsync(recipientDID, { methods: [] })
    expect(await identity.agreeKey(shared.ephemeralPublicKey)).toEqual(shared.sharedSecret)
    if (didMethod === 'peer:4') {
      expect(identity.longForm).not.toBe(identity.id)
      expect(recipientDID).toBe(identity.longForm)
      await expect(
        suite.wrap({
          ...address,
          runtime,
          contentKey,
          factors: [{ kind: 'did', recipientDID: identity.id }],
        }),
      ).rejects.toThrow(/short form/i)
    }
  })

  const invalidFactors: Array<{ factors: Array<FactorInput> }> = [
    { factors: [] },
    { factors: [{ kind: 'pin', input: pin, cost }] },
    {
      factors: [
        { kind: 'passphrase', input: passphrase, cost },
        { kind: 'passphrase', input: passphrase, cost },
      ],
    },
  ]
  test.each(invalidFactors)('refuses invalid factor lists ($factors)', async ({ factors }) => {
    await expect(
      suite.wrap({
        ...address,
        runtime,
        contentKey: suite.generateContentKey(runtime),
        factors,
      }),
    ).rejects.toThrow(InvalidVaultFactors)
  })

  test('entry bytes round-trip and authenticate their entry address', () => {
    const contentKey = suite.generateContentKey(runtime)
    const entryID = 'binary-entry'
    const bytes = new Uint8Array([0, 0x80, 0xff, 0xc3, 0x28])
    const encrypted = suite.encryptEntry({
      ...address,
      runtime,
      contentKey,
      entryID,
      plaintext: bytes,
    })
    expect(suite.decryptEntry({ ...address, ...encrypted, contentKey, entryID })).toEqual(bytes)
    expect(() =>
      suite.decryptEntry({
        ...address,
        ...encrypted,
        contentKey,
        entryID: 'another-entry',
      }),
    ).toThrow(VaultTampered)
  })

  test('a host blob uses only the device agreement key and never prompts', async () => {
    const device = randomIdentity()
    const prompt = vi.fn(() => {
      throw new Error('message-path identity attempted to prompt')
    })
    const agreeKey = vi.fn(async (epk: Uint8Array) => await device.agreeKey(epk))
    const identity = { id: device.id, agreeKey, prompt }
    const contentKey = suite.generateContentKey(runtime)
    const wrapped = await suite.wrap({
      ...address,
      runtime,
      contentKey,
      factors: [{ kind: 'did', recipientDID: device.id }],
    })
    const opened = await suite.unwrap({ ...openParams(wrapped), identity })
    for (const body of [plaintext, new Uint8Array(8192).fill(73)]) {
      const encrypted = suite.encryptEntry({
        ...address,
        runtime,
        contentKey: opened,
        entryID: 'mls-current-state',
        plaintext: body,
      })
      expect(
        suite.decryptEntry({
          ...address,
          ...encrypted,
          contentKey: opened,
          entryID: 'mls-current-state',
        }),
      ).toEqual(body)
    }
    expect(agreeKey).toHaveBeenCalledTimes(1)
    expect(prompt).not.toHaveBeenCalled()
  })
})
