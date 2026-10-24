import { deriveSharedSecret } from '@kokuin/jwe'
import { createIdentity, randomIdentity } from '@kokuin/token'
import { fromB64, toB64 } from '@sozai/codec'
import { createRuntime } from '@sozai/runtime'
import { describe, expect, test } from 'vitest'

import {
  InvalidVaultFactors,
  NoAvailableFactor,
  UnsupportedVaultSuite,
  VaultSecretRejected,
  VaultTampered,
} from '../src/errors.js'
import type { FactorDescriptor } from '../src/factors.js'
import {
  type Argon2Cost,
  DEFAULT_ARGON2_COST,
  getSuite,
  isSupportedSuite,
  SUITE_VAULT_1,
} from '../src/suite.js'

const runtime = createRuntime()
const suite = getSuite(SUITE_VAULT_1)

const KEY_ID = 'k-key-1'
const WRAPPING_ID = 'wrap-1'

function epkOf(descriptor: FactorDescriptor): string {
  const epk = descriptor.params.epk
  if (typeof epk !== 'string') {
    throw new Error(`${descriptor.kind} descriptor carries no epk`)
  }
  return epk
}
const ENTRY_ID = 'k-entry-1'

async function wrapFor(recipientDID: string, contentKey: Uint8Array, keyVersion = 1) {
  return await suite.wrap({
    runtime,
    contentKey,
    factors: [{ kind: 'did', recipientDID }],
    wrappingID: WRAPPING_ID,
    keyID: KEY_ID,
    keyVersion,
  })
}

describe('suite 1 wrapping', () => {
  test('a content key wraps and unwraps on the recipient identity', async () => {
    const identity = randomIdentity()
    const contentKey = suite.generateContentKey(runtime)

    const { descriptors, iv, wrappedKey } = await wrapFor(identity.id, contentKey)
    const recovered = await suite.unwrap({
      identity,
      descriptors,
      iv,
      wrappedKey,
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    expect(recovered).toEqual(contentKey)
  })

  test('sender and recipient derive identical factor secret bytes', async () => {
    const identity = randomIdentity()
    const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(identity.id)

    expect(await identity.agreeKey(ephemeralPublicKey)).toEqual(sharedSecret)
    expect(sharedSecret).toHaveLength(32)
  })

  test('a tampered epk does not open the wrapping', async () => {
    const identity = randomIdentity()
    const { descriptors, iv, wrappedKey } = await wrapFor(
      identity.id,
      suite.generateContentKey(runtime),
    )

    const descriptor = descriptors[0]
    if (descriptor == null) {
      throw new Error('wrap produced no descriptor')
    }
    const bytes = fromB64(epkOf(descriptor))
    bytes[0] = (bytes[0] ?? 0) ^ 0x01
    const tampered: Array<FactorDescriptor> = [
      { ...descriptor, params: { ...descriptor.params, epk: toB64(bytes) } },
    ]

    await expect(
      suite.unwrap({
        identity,
        descriptors: tampered,
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(VaultSecretRejected)
  })

  test('a peer:4 recipient wraps and unwraps, addressed by long form', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const contentKey = suite.generateContentKey(runtime)

    const { descriptors, iv, wrappedKey } = await wrapFor(identity.longForm, contentKey)
    const recovered = await suite.unwrap({
      identity,
      descriptors,
      iv,
      wrappedKey,
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    expect(recovered).toEqual(contentKey)
  })

  test('a peer:4 SHORT form is refused at wrap time, not silently mis-wrapped', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })

    await expect(wrapFor(identity.id, suite.generateContentKey(runtime))).rejects.toThrow(
      /short form/i,
    )
  })

  test('a peer:4 identity with no KEM key cannot hold a vault', async () => {
    const sigOnly = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })

    await expect(wrapFor(sigOnly.longForm, suite.generateContentKey(runtime))).rejects.toThrow(
      /keyAgreement|KEM/i,
    )
  })

  test('a wrapping made for A does not open for B', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()
    const contentKey = suite.generateContentKey(runtime)

    const { descriptors, iv, wrappedKey } = await wrapFor(alice.id, contentKey)

    await expect(
      suite.unwrap({
        identity: bob,
        descriptors,
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow()
  })

  test('a device with no decrypting identity reports the missing factor by name', async () => {
    const identity = randomIdentity()
    const { descriptors, iv, wrappedKey } = await wrapFor(
      identity.id,
      suite.generateContentKey(runtime),
    )

    await expect(
      suite.unwrap({
        identity: null,
        descriptors,
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(NoAvailableFactor)
  })

  describe('the AAD binds the factor descriptors', () => {
    test('unauthenticated descriptor editing yields VaultSecretRejected', async () => {
      const identity = randomIdentity()
      const { descriptors, iv, wrappedKey } = await wrapFor(
        identity.id,
        suite.generateContentKey(runtime),
      )

      const edited = descriptors.map((d) => ({
        ...d,
        params: { ...d.params, recipient: 'did:key:someone-else' },
      }))

      await expect(
        suite.unwrap({
          identity,
          descriptors: edited,
          iv,
          wrappedKey,
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(VaultSecretRejected)
    })

    test('a wrapping does not open under a different wrapping id', async () => {
      const identity = randomIdentity()
      const { descriptors, iv, wrappedKey } = await wrapFor(
        identity.id,
        suite.generateContentKey(runtime),
      )

      await expect(
        suite.unwrap({
          identity,
          descriptors,
          iv,
          wrappedKey,
          wrappingID: 'some-other-wrapping',
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(VaultSecretRejected)
    })
  })

  describe('the KEK concatenates factor secrets in order', () => {
    test('reordering the descriptors fails', async () => {
      const identity = randomIdentity()
      const wrapped = await suite.wrap({
        runtime,
        contentKey: suite.generateContentKey(runtime),
        factors: [
          { kind: 'did', recipientDID: identity.id },
          { kind: 'did', recipientDID: identity.id },
        ],
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      })

      const reversed = [...wrapped.descriptors].reverse()
      await expect(
        suite.unwrap({
          identity,
          descriptors: reversed,
          iv: wrapped.iv,
          wrappedKey: wrapped.wrappedKey,
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(VaultSecretRejected)
    })
  })

  describe('info binds the key version', () => {
    test('a wrapping at version N does not open at version N+1', async () => {
      const identity = randomIdentity()
      const { descriptors, iv, wrappedKey } = await wrapFor(
        identity.id,
        suite.generateContentKey(runtime),
        1,
      )

      await expect(
        suite.unwrap({
          identity,
          descriptors,
          iv,
          wrappedKey,
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 2,
        }),
      ).rejects.toThrow(VaultSecretRejected)
    })

    test('a wrapping does not open under a different key id', async () => {
      const identity = randomIdentity()
      const { descriptors, iv, wrappedKey } = await wrapFor(
        identity.id,
        suite.generateContentKey(runtime),
      )

      await expect(
        suite.unwrap({
          identity,
          descriptors,
          iv,
          wrappedKey,
          wrappingID: WRAPPING_ID,
          keyID: 'k-some-other-key',
          keyVersion: 1,
        }),
      ).rejects.toThrow(VaultSecretRejected)
    })
  })
})

describe('suite 1 passphrase and pin factors', () => {
  const testCost: Argon2Cost = { m: 64, t: 1, p: 1 }
  const passphraseInput = new TextEncoder().encode('correct horse battery staple')
  const pinInput = new TextEncoder().encode('1234')

  test('a passphrase factor stands alone and round-trips', async () => {
    const contentKey = suite.generateContentKey(runtime)
    const { descriptors, iv, wrappedKey } = await suite.wrap({
      runtime,
      contentKey,
      factors: [{ kind: 'passphrase', input: passphraseInput, cost: testCost }],
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    const recovered = await suite.unwrap({
      identity: null,
      descriptors,
      inputs: { passphrase: passphraseInput },
      iv,
      wrappedKey,
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    expect(recovered).toEqual(contentKey)
  })

  test('a different passphrase does not open it', async () => {
    const { descriptors, iv, wrappedKey } = await suite.wrap({
      runtime,
      contentKey: suite.generateContentKey(runtime),
      factors: [{ kind: 'passphrase', input: passphraseInput, cost: testCost }],
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    await expect(
      suite.unwrap({
        identity: null,
        descriptors,
        inputs: { passphrase: new TextEncoder().encode('correct horse battery stapl') },
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow()
  })

  test('a did and a pin factor are an AND: both are required', async () => {
    const identity = randomIdentity()
    const contentKey = suite.generateContentKey(runtime)
    const { descriptors, iv, wrappedKey } = await suite.wrap({
      runtime,
      contentKey,
      factors: [
        { kind: 'did', recipientDID: identity.id },
        { kind: 'pin', input: pinInput, cost: testCost },
      ],
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    const unwrap = (inputs?: { pin?: Uint8Array }) =>
      suite.unwrap({
        identity,
        descriptors,
        inputs,
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      })

    expect(await unwrap({ pin: pinInput })).toEqual(contentKey)

    await expect(unwrap()).rejects.toThrow(NoAvailableFactor)
    await expect(unwrap({ pin: new TextEncoder().encode('4321') })).rejects.toThrow()
  })

  test('lowering a stored cost parameter fails', async () => {
    const { descriptors, iv, wrappedKey } = await suite.wrap({
      runtime,
      contentKey: suite.generateContentKey(runtime),
      factors: [{ kind: 'passphrase', input: passphraseInput, cost: testCost }],
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    const weakened = descriptors.map((descriptor) => ({
      ...descriptor,
      params: { ...descriptor.params, m: 8 },
    }))

    await expect(
      suite.unwrap({
        identity: null,
        descriptors: weakened,
        inputs: { passphrase: passphraseInput },
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(VaultSecretRejected)
  })

  test('a factor with no explicit cost is written at the production default', async () => {
    const { descriptors } = await suite.wrap({
      runtime,
      contentKey: suite.generateContentKey(runtime),
      factors: [{ kind: 'passphrase', input: passphraseInput }],
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    expect(descriptors[0]?.params).toMatchObject(DEFAULT_ARGON2_COST)
    expect(DEFAULT_ARGON2_COST.m).toBeGreaterThanOrEqual(19456)
  })

  test('each wrapping gets its own salt', async () => {
    const wrapOnce = () =>
      suite.wrap({
        runtime,
        contentKey: suite.generateContentKey(runtime),
        factors: [{ kind: 'passphrase', input: passphraseInput, cost: testCost }],
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      })

    const first = await wrapOnce()
    const second = await wrapOnce()
    expect(first.descriptors[0]?.params.salt).not.toBe(second.descriptors[0]?.params.salt)
  })

  describe('a wrapping ANDing nothing at all', () => {
    test('is refused at creation', async () => {
      await expect(
        suite.wrap({
          runtime,
          contentKey: suite.generateContentKey(runtime),
          factors: [],
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(InvalidVaultFactors)
    })

    test('is refused on unwrap too', async () => {
      await expect(
        suite.unwrap({
          identity: null,
          descriptors: [],
          iv: new Uint8Array(12),
          wrappedKey: new Uint8Array(48),
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(InvalidVaultFactors)
    })
  })

  test('two factors of the same kind are refused at creation', async () => {
    await expect(
      suite.wrap({
        runtime,
        contentKey: suite.generateContentKey(runtime),
        factors: [
          { kind: 'pin', input: pinInput, cost: testCost },
          { kind: 'pin', input: pinInput, cost: testCost },
        ],
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(InvalidVaultFactors)
  })

  describe('a pin is worthless without a did in the same wrapping', () => {
    test('a pin-only wrapping is refused at creation', async () => {
      await expect(
        suite.wrap({
          runtime,
          contentKey: suite.generateContentKey(runtime),
          factors: [{ kind: 'pin', input: pinInput, cost: testCost }],
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(InvalidVaultFactors)
    })

    test('a passphrase does not substitute for the did', async () => {
      await expect(
        suite.wrap({
          runtime,
          contentKey: suite.generateContentKey(runtime),
          factors: [
            { kind: 'passphrase', input: passphraseInput, cost: testCost },
            { kind: 'pin', input: pinInput, cost: testCost },
          ],
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(InvalidVaultFactors)
    })

    test('a stored pin-only wrapping is refused on unwrap too', async () => {
      await expect(
        suite.unwrap({
          identity: null,
          descriptors: [{ kind: 'pin', params: { salt: 'AAAA', m: 64, t: 1, p: 1 } }],
          inputs: { pin: pinInput },
          iv: new Uint8Array(12),
          wrappedKey: new Uint8Array(48),
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(InvalidVaultFactors)
    })
  })

  test('a descriptor with no usable Argon2 parameters is refused, not run at zero cost', async () => {
    await expect(
      suite.unwrap({
        identity: null,
        descriptors: [{ kind: 'passphrase', params: { salt: 'AAAA' } }],
        inputs: { passphrase: passphraseInput },
        iv: new Uint8Array(12),
        wrappedKey: new Uint8Array(48),
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(VaultTampered)
  })

  test.each([
    { m: -1, t: 1, p: 1 },
    { m: 64.5, t: 1, p: 1 },
    { m: 64, t: Number.POSITIVE_INFINITY, p: 1 },
    { m: 64, t: 1, p: 0 },
  ])(
    'a persisted descriptor with invalid Argon2 cost is refused before the KDF: %o',
    async (cost) => {
      await expect(
        suite.unwrap({
          identity: null,
          descriptors: [
            { kind: 'passphrase', params: { salt: toB64(new Uint8Array(16)), ...cost } },
          ],
          inputs: { passphrase: passphraseInput },
          iv: new Uint8Array(12),
          wrappedKey: new Uint8Array(48),
          wrappingID: WRAPPING_ID,
          keyID: KEY_ID,
          keyVersion: 1,
        }),
      ).rejects.toThrow(VaultTampered)
    },
  )

  test('a persisted descriptor with the wrong salt length is refused before the KDF', async () => {
    await expect(
      suite.unwrap({
        identity: null,
        descriptors: [{ kind: 'passphrase', params: { salt: 'AAAA', m: 64, t: 1, p: 1 } }],
        inputs: { passphrase: passphraseInput },
        iv: new Uint8Array(12),
        wrappedKey: new Uint8Array(48),
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(VaultTampered)
  })

  test('creation rejects an invalid Argon2 cost through the factor-validation error', async () => {
    await expect(
      suite.wrap({
        runtime,
        contentKey: suite.generateContentKey(runtime),
        factors: [{ kind: 'passphrase', input: passphraseInput, cost: { m: 64, t: 0, p: 1 } }],
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(InvalidVaultFactors)
  })
})

describe('suite 1 attributes an unwrap failure', () => {
  const testCost: Argon2Cost = { m: 64, t: 1, p: 1 }
  const passphraseInput = new TextEncoder().encode('correct horse battery staple')
  const pinInput = new TextEncoder().encode('1234')

  test('a did-only authentication failure is an unclassified secret rejection', async () => {
    const identity = randomIdentity()
    const { descriptors, iv, wrappedKey } = await wrapFor(
      identity.id,
      suite.generateContentKey(runtime),
    )

    await expect(
      suite.unwrap({
        identity,
        descriptors,
        iv,
        wrappedKey,
        wrappingID: 'some-other-wrapping',
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(VaultSecretRejected)
  })

  test('a wrapping addressed to another identity is not distinguishable here', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()
    const { descriptors, iv, wrappedKey } = await wrapFor(
      alice.id,
      suite.generateContentKey(runtime),
    )

    await expect(
      suite.unwrap({
        identity: bob,
        descriptors,
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      }),
    ).rejects.toThrow(VaultSecretRejected)
  })

  test('a wrong passphrase is retryable and names the kind', async () => {
    const { descriptors, iv, wrappedKey } = await suite.wrap({
      runtime,
      contentKey: suite.generateContentKey(runtime),
      factors: [{ kind: 'passphrase', input: passphraseInput, cost: testCost }],
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    const error = await suite
      .unwrap({
        identity: null,
        descriptors,
        inputs: { passphrase: new TextEncoder().encode('wrong') },
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      })
      .catch((cause: unknown) => cause)

    expect(error).toBeInstanceOf(VaultSecretRejected)
    expect((error as VaultSecretRejected).kinds).toEqual(['passphrase'])

    expect(error).not.toBeInstanceOf(VaultTampered)
  })

  test('a correct pin against an edited did descriptor still reports the pin', async () => {
    const identity = randomIdentity()
    const { descriptors, iv, wrappedKey } = await suite.wrap({
      runtime,
      contentKey: suite.generateContentKey(runtime),
      factors: [
        { kind: 'did', recipientDID: identity.id },
        { kind: 'pin', input: pinInput, cost: testCost },
      ],
      wrappingID: WRAPPING_ID,
      keyID: KEY_ID,
      keyVersion: 1,
    })

    const edited = descriptors.map((descriptor) =>
      descriptor.kind === 'did'
        ? { ...descriptor, params: { ...descriptor.params, recipient: 'did:key:someone-else' } }
        : descriptor,
    )

    const error = await suite
      .unwrap({
        identity,
        descriptors: edited,
        inputs: { pin: pinInput },
        iv,
        wrappedKey,
        wrappingID: WRAPPING_ID,
        keyID: KEY_ID,
        keyVersion: 1,
      })
      .catch((cause: unknown) => cause)

    expect(error).toBeInstanceOf(VaultSecretRejected)
    expect((error as VaultSecretRejected).kinds).toEqual(['pin'])
    expect((error as Error).message).toMatch(/may have been altered/)
  })
})

describe('suite 1 entries', () => {
  const contentKey = new Uint8Array(32).fill(7)
  const plaintext = new TextEncoder().encode('secret value')

  function encrypt(keyVersion = 1, entryID = ENTRY_ID) {
    return suite.encryptEntry({
      runtime,
      contentKey,
      plaintext,
      keyID: KEY_ID,
      keyVersion,
      entryID,
    })
  }

  test('round-trips under the same key, version and entry', () => {
    const { iv, ciphertext } = encrypt()
    expect(
      suite.decryptEntry({
        contentKey,
        iv,
        ciphertext,
        keyID: KEY_ID,
        keyVersion: 1,
        entryID: ENTRY_ID,
      }),
    ).toEqual(plaintext)
  })

  test('ciphertext does not move between entries', () => {
    const { iv, ciphertext } = encrypt()
    expect(() =>
      suite.decryptEntry({
        contentKey,
        iv,
        ciphertext,
        keyID: KEY_ID,
        keyVersion: 1,
        entryID: 'k-entry-other',
      }),
    ).toThrow(VaultTampered)
  })

  test('ciphertext does not read under a different key version', () => {
    const { iv, ciphertext } = encrypt(1)
    expect(() =>
      suite.decryptEntry({
        contentKey,
        iv,
        ciphertext,
        keyID: KEY_ID,
        keyVersion: 2,
        entryID: ENTRY_ID,
      }),
    ).toThrow(VaultTampered)
  })

  test('an altered ciphertext byte fails', () => {
    const { iv, ciphertext } = encrypt()
    const altered = new Uint8Array(ciphertext)
    altered[0] = (altered[0] ?? 0) ^ 0xff
    expect(() =>
      suite.decryptEntry({
        contentKey,
        iv,
        ciphertext: altered,
        keyID: KEY_ID,
        keyVersion: 1,
        entryID: ENTRY_ID,
      }),
    ).toThrow(VaultTampered)
  })
})

describe('the suite registry', () => {
  test('an unknown suite is named, not swallowed', () => {
    expect(isSupportedSuite(SUITE_VAULT_1)).toBe(true)
    expect(isSupportedSuite(99)).toBe(false)
    expect(() => getSuite(99)).toThrow(UnsupportedVaultSuite)
  })
})
