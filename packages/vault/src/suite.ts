import { deriveSharedSecretAsync } from '@kokuin/jwe'
import type { CryptoOptions, KeyAgreementIdentity, MethodRegistry } from '@kokuin/token'
import { gcm } from '@noble/ciphers/aes.js'
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes } from '@noble/hashes/utils.js'
import { canonicalStringify, fromB64, fromUTF, toB64 } from '@sozai/codec'
import type { Runtime } from '@sozai/runtime'

import { checkDescriptorDigest, descriptorDigest } from './digest.js'
import {
  InvalidVaultFactors,
  NoAvailableFactor,
  UnsupportedVaultSuite,
  VaultSecretRejected,
  VaultTampered,
} from './errors.js'
import type { FactorDescriptor } from './factors.js'

type DeriveKEKParams = {
  secrets: Array<Uint8Array>
  wrappingID: string
  suiteID: number
  keyID: string
  keyVersion: number
}
type EntryAADParams = { suiteID: number; keyID: string; keyVersion: number; entryID: string }

/** X25519 / HKDF-SHA256 / Argon2id / A256GCM. */
export const SUITE_VAULT_1 = 1

const IV_LENGTH = 12
const CONTENT_KEY_LENGTH = 32
const FACTOR_SECRET_LENGTH = 32
const SALT_LENGTH = 16
const WRAP_INFO_PREFIX = 'kokuin/vault/wrap/v1'
const ARGON2_COST_LIMITS = {
  m: { min: 8, max: 262_144 },
  t: { min: 1, max: 10 },
  p: { min: 1, max: 16 },
} as const

export type Argon2Cost = {
  m: number
  t: number
  p: number
}

/** Memory KiB, passes, lanes. Costs are per wrapping, independent of suite version. */
export const DEFAULT_ARGON2_COST: Argon2Cost = { m: 19456, t: 2, p: 1 }

function invalidArgon2Cost(cost: Argon2Cost): string | null {
  for (const name of ['m', 't', 'p'] as const) {
    const value = cost[name]
    const limits = ARGON2_COST_LIMITS[name]

    if (!Number.isSafeInteger(value) || value < limits.min || value > limits.max) {
      return `${name} must be an integer from ${limits.min} through ${limits.max}`
    }
  }

  return null
}

export type SecretFactorKind = 'passphrase' | 'pin'

export type FactorInput =
  | { kind: 'did'; recipientDID: string }
  | { kind: SecretFactorKind; input: Uint8Array; cost?: Argon2Cost }

export type FactorInputs = Partial<Record<SecretFactorKind, Uint8Array>>

export type VaultSuite = {
  id: number
  name: string

  generateContentKey(runtime: Runtime): Uint8Array
  wrap(params: WrapParams): Promise<WrapResult>
  unwrap(params: UnwrapParams): Promise<Uint8Array>
  encryptEntry(params: EncryptEntryParams): EncryptEntryResult
  decryptEntry(params: DecryptEntryParams): Uint8Array
}

export type WrapParams = CryptoOptions & {
  runtime: Runtime
  contentKey: Uint8Array
  factors: Array<FactorInput>
  wrappingID: string
  keyID: string
  keyVersion: number
  methods?: MethodRegistry
}

export type EncryptEntryResult = {
  iv: Uint8Array
  ciphertext: Uint8Array
}

export type WrapResult = {
  descriptorDigest: string
  descriptors: Array<FactorDescriptor>
  iv: Uint8Array
  wrappedKey: Uint8Array
}

export type UnwrapParams = CryptoOptions & {
  /** Trusted local state or authenticated metadata, independent of presented descriptors. */
  expectedDescriptorDigest?: string
  /** Informational digest from the presented wrapping, never used as a trust anchor. */
  descriptorDigest?: string
  identity: KeyAgreementIdentity | null
  descriptors: Array<FactorDescriptor>
  inputs?: FactorInputs
  iv: Uint8Array
  wrappedKey: Uint8Array
  wrappingID: string
  keyID: string
  keyVersion: number
}

export type EncryptEntryParams = {
  runtime: Runtime
  contentKey: Uint8Array
  plaintext: Uint8Array
  keyID: string
  keyVersion: number
  entryID: string
}

export type DecryptEntryParams = {
  contentKey: Uint8Array
  iv: Uint8Array
  ciphertext: Uint8Array
  keyID: string
  keyVersion: number
  entryID: string
}

// Factor order, wrapping salt, and suite/key/version binding are part of the wire scheme.
function deriveKEK({
  secrets,
  wrappingID,
  suiteID,
  keyID,
  keyVersion,
}: DeriveKEKParams): Uint8Array {
  const info = fromUTF(`${WRAP_INFO_PREFIX}:${suiteID}:${keyID}:${keyVersion}`)

  return hkdf(sha256, concatBytes(...secrets), fromUTF(wrappingID), info, CONTENT_KEY_LENGTH)
}

// Canonical object keys, ordered descriptors.
function wrappingAAD(descriptors: Array<FactorDescriptor>): Uint8Array {
  return fromUTF(canonicalStringify(descriptors))
}

function entryAAD({ suiteID, keyID, keyVersion, entryID }: EntryAADParams): Uint8Array {
  return fromUTF(`kokuin/vault/entry/v1:${suiteID}:${keyID}:${keyVersion}:${entryID}`)
}

async function didFactorSecretForSender(
  recipientDID: string,
  methods?: MethodRegistry,
): Promise<{
  secret: Uint8Array
  params: Record<string, unknown>
}> {
  const { sharedSecret, ephemeralPublicKey } = await deriveSharedSecretAsync(recipientDID, {
    methods: methods ?? [],
  })

  return {
    secret: sharedSecret,
    params: { recipient: recipientDID, epk: toB64(ephemeralPublicKey) },
  }
}

async function secretFactorForSender(
  runtime: Runtime,
  input: Uint8Array,
  cost: Argon2Cost,
): Promise<{ secret: Uint8Array; params: Record<string, unknown> }> {
  const invalid = invalidArgon2Cost(cost)

  if (invalid != null) {
    throw new InvalidVaultFactors({ reason: `invalid Argon2 cost: ${invalid}` })
  }

  const salt = runtime.getRandomValues(new Uint8Array(SALT_LENGTH))
  const secret = await argon2idAsync(input, salt, { ...cost, dkLen: FACTOR_SECRET_LENGTH })

  return { secret, params: { salt: toB64(salt), ...cost } }
}

async function secretFactorForRecipient(
  kind: SecretFactorKind,
  input: Uint8Array | undefined,
  params: Record<string, unknown>,
): Promise<Uint8Array> {
  if (input == null) {
    throw new NoAvailableFactor({ kind: kind })
  }

  const { salt, m, t, p } = params

  if (
    typeof salt !== 'string' ||
    typeof m !== 'number' ||
    typeof t !== 'number' ||
    typeof p !== 'number'
  ) {
    throw new VaultTampered({
      message: `${kind} factor descriptor carries no usable Argon2 parameters`,
    })
  }

  const invalid = invalidArgon2Cost({ m, t, p })

  if (invalid != null) {
    throw new VaultTampered({
      message: `${kind} factor descriptor has invalid Argon2 cost: ${invalid}`,
    })
  }

  let decodedSalt: Uint8Array

  try {
    decodedSalt = fromB64(salt)
  } catch (cause) {
    // biome-ignore lint/style/useErrorCause: the params object forwards options.cause.
    throw new VaultTampered({
      message: `${kind} factor descriptor carries an invalid Argon2 salt`,
      options: {
        cause,
      },
    })
  }

  if (decodedSalt.length !== SALT_LENGTH) {
    throw new VaultTampered({
      message: `${kind} factor descriptor Argon2 salt must be ${SALT_LENGTH} bytes`,
    })
  }

  return await argon2idAsync(input, decodedSalt, { m, t, p, dkLen: FACTOR_SECRET_LENGTH })
}

// A PIN requires device possession; a passphrase alone does not substitute for it.
export function validateFactorList(kinds: Array<string>): void {
  if (kinds.length === 0) {
    throw new InvalidVaultFactors({ reason: 'a wrapping needs at least one factor' })
  }

  const seen = new Set<string>()

  for (const kind of kinds) {
    if (kind === 'did') {
      continue
    }

    if (seen.has(kind)) {
      throw new InvalidVaultFactors({ reason: `duplicate "${kind}" factor` })
    }

    seen.add(kind)
  }

  if (seen.has('pin') && !kinds.includes('did')) {
    throw new InvalidVaultFactors({
      reason: 'a "pin" factor requires a "did" factor in the same wrapping',
    })
  }
}

async function didFactorSecretForRecipient(
  identity: KeyAgreementIdentity | null,
  params: Record<string, unknown>,
): Promise<Uint8Array> {
  if (identity == null) {
    throw new NoAvailableFactor({ kind: 'did' })
  }

  const epk = params.epk

  if (typeof epk !== 'string') {
    throw new VaultTampered({ message: 'did factor descriptor carries no epk' })
  }

  return await identity.agreeKey(fromB64(epk))
}

const suite1: VaultSuite = {
  id: SUITE_VAULT_1,
  name: 'VAULT_1',

  generateContentKey(runtime) {
    return runtime.getRandomValues(new Uint8Array(CONTENT_KEY_LENGTH))
  },

  async wrap(input) {
    const params = {
      ...input,
      contentKey: new Uint8Array(input.contentKey),
      factors: input.factors.map((factor) => {
        return factor.kind === 'did'
          ? { ...factor }
          : {
              ...factor,
              input: new Uint8Array(factor.input),
              ...(factor.cost === undefined ? {} : { cost: { ...factor.cost } }),
            }
      }),
    }
    validateFactorList(params.factors.map((factor) => factor.kind))

    const secrets: Array<Uint8Array> = []
    const descriptors: Array<FactorDescriptor> = []

    for (const factor of params.factors) {
      switch (factor.kind) {
        case 'did': {
          const { secret, params: factorParams } = await didFactorSecretForSender(
            factor.recipientDID,
            params.methods,
          )

          secrets.push(secret)
          descriptors.push({ kind: 'did', params: factorParams })
          break
        }
        case 'passphrase':
        case 'pin': {
          const { secret, params: factorParams } = await secretFactorForSender(
            params.runtime,
            factor.input,
            factor.cost ?? DEFAULT_ARGON2_COST,
          )

          secrets.push(secret)
          descriptors.push({ kind: factor.kind, params: factorParams })
          break
        }
      }
    }

    const kek = deriveKEK({
      secrets: secrets,
      wrappingID: params.wrappingID,
      suiteID: SUITE_VAULT_1,
      keyID: params.keyID,
      keyVersion: params.keyVersion,
    })
    const iv = params.runtime.getRandomValues(new Uint8Array(IV_LENGTH))

    return {
      descriptors,
      descriptorDigest: await descriptorDigest(descriptors, params),
      iv,
      wrappedKey: gcm(kek, iv, wrappingAAD(descriptors)).encrypt(params.contentKey),
    }
  },

  async unwrap(input) {
    const params = {
      ...input,
      descriptors: JSON.parse(JSON.stringify(input.descriptors)) as Array<FactorDescriptor>,
      iv: new Uint8Array(input.iv),
      wrappedKey: new Uint8Array(input.wrappedKey),
      inputs:
        input.inputs === undefined
          ? undefined
          : Object.fromEntries(
              Object.entries(input.inputs).flatMap(([kind, bytes]) => {
                return bytes === undefined ? [] : [[kind, new Uint8Array(bytes)]]
              }),
            ),
    }
    if (params.expectedDescriptorDigest !== undefined) {
      await checkDescriptorDigest({
        crypto: params.crypto,
        descriptors: params.descriptors,
        expectedDescriptorDigest: params.expectedDescriptorDigest,
      })
    }

    validateFactorList(params.descriptors.map((descriptor) => descriptor.kind))

    const secrets: Array<Uint8Array> = []
    const userSuppliedKinds: Array<SecretFactorKind> = []

    for (const descriptor of params.descriptors) {
      switch (descriptor.kind) {
        case 'did':
          secrets.push(await didFactorSecretForRecipient(params.identity, descriptor.params))
          break
        case 'passphrase':
        case 'pin':
          secrets.push(
            await secretFactorForRecipient(
              descriptor.kind,
              params.inputs?.[descriptor.kind],
              descriptor.params,
            ),
          )
          userSuppliedKinds.push(descriptor.kind)
          break
        default:
          throw new NoAvailableFactor({ kind: descriptor.kind })
      }
    }

    const kek = deriveKEK({
      secrets: secrets,
      wrappingID: params.wrappingID,
      suiteID: SUITE_VAULT_1,
      keyID: params.keyID,
      keyVersion: params.keyVersion,
    })

    try {
      return gcm(kek, params.iv, wrappingAAD(params.descriptors)).decrypt(params.wrappedKey)
    } catch (cause) {
      // A tag failure cannot attribute corruption versus a wrong secret, including DID-only wraps.
      // biome-ignore lint/style/useErrorCause: the params object forwards options.cause.
      throw new VaultSecretRejected({
        kinds: userSuppliedKinds,
        options: { cause, keyID: params.keyID },
      })
    }
  },

  encryptEntry(params) {
    const iv = params.runtime.getRandomValues(new Uint8Array(IV_LENGTH))
    const aad = entryAAD({
      suiteID: SUITE_VAULT_1,
      keyID: params.keyID,
      keyVersion: params.keyVersion,
      entryID: params.entryID,
    })

    return {
      iv,
      ciphertext: gcm(params.contentKey, iv, aad).encrypt(params.plaintext),
    }
  },

  decryptEntry(params) {
    const aad = entryAAD({
      suiteID: SUITE_VAULT_1,
      keyID: params.keyID,
      keyVersion: params.keyVersion,
      entryID: params.entryID,
    })

    try {
      return gcm(params.contentKey, params.iv, aad).decrypt(params.ciphertext)
    } catch (cause) {
      // biome-ignore lint/style/useErrorCause: the params object forwards options.cause.
      throw new VaultTampered({
        message:
          'vault entry failed authentication: it was altered, or is being read under the wrong key version',
        options: { cause },
      })
    }
  },
}

const SUITES = new Map<number, VaultSuite>([[SUITE_VAULT_1, suite1]])

export function getSuite(id: number): VaultSuite {
  const suite = SUITES.get(id)

  if (suite == null) {
    throw new UnsupportedVaultSuite({ suite: id })
  }

  return suite
}

export function isSupportedSuite(id: number): boolean {
  return SUITES.has(id)
}

export type WrappedKey = WrapResult

export type EncryptedEntry = EncryptEntryResult

export type CryptoAddress = { keyID: string; keyVersion: number }
