import { nobleCrypto } from '@kokuin/crypto'
import type { CryptoOptions } from '@kokuin/token'
import { fromUTF, toB64U } from '@sozai/codec'
import { canonicalize } from '@sozai/json'

import { VaultTampered } from './errors.js'
import type { FactorDescriptor } from './factors.js'

function descriptorJSON(descriptors: ReadonlyArray<FactorDescriptor>): string {
  const json = canonicalize(descriptors)
  if (json == null) throw new TypeError('Factor descriptors have no JSON representation')
  return json
}

export async function digestParts(parts: Array<string>, options?: CryptoOptions): Promise<string> {
  const framed = parts.map((part) => `${part.length}:${part}`).join('')

  return toB64U(await (options?.crypto ?? nobleCrypto).blake3(fromUTF(framed), 32))
}

export type VaultKeyDigestInput = {
  ownerDID: string
  suite: number
  version: number
  state: string
}

export type VaultWrappingDigestInput = {
  wrappingID: string
  recipientDID: string | null
  iv: string
  wrappedKey: string
  factors: Array<FactorDescriptor>
}

export type VaultEntryDigestInput = {
  entryID: string
  iv: string
  ciphertext: string
  hlc: string
}

export function vaultKeyDigest(key: VaultKeyDigestInput, options?: CryptoOptions): Promise<string> {
  return digestParts([key.ownerDID, String(key.suite), String(key.version), key.state], options)
}

export function vaultWrappingDigest(
  wrapping: VaultWrappingDigestInput,
  options?: CryptoOptions,
): Promise<string> {
  return digestParts(
    [
      wrapping.wrappingID,
      wrapping.recipientDID ?? '',
      wrapping.iv,
      wrapping.wrappedKey,
      descriptorJSON(wrapping.factors),
    ],
    options,
  )
}

export function vaultEntriesDigest(
  entries: ReadonlyArray<VaultEntryDigestInput>,
  options?: CryptoOptions,
): Promise<string> {
  const ordered = [...entries].sort((left, right) => {
    return left.entryID < right.entryID ? -1 : left.entryID > right.entryID ? 1 : 0
  })

  return digestParts(
    ordered.flatMap((entry) => [entry.entryID, entry.iv, entry.ciphertext, entry.hlc]),
    options,
  )
}

export function vaultEntryDigest(
  entry: VaultEntryDigestInput,
  options?: CryptoOptions,
): Promise<string> {
  return vaultEntriesDigest([entry], options)
}

/** Same canonical descriptor encoding and length framing as the wrapping digest. */
export function descriptorDigest(
  descriptors: Array<FactorDescriptor>,
  options?: CryptoOptions,
): Promise<string> {
  return digestParts([descriptorJSON(descriptors)], options)
}

export async function checkDescriptorDigest(
  params: CryptoOptions & {
    descriptors: Array<FactorDescriptor>
    expectedDescriptorDigest: string
  },
): Promise<void> {
  const { descriptors, expectedDescriptorDigest, crypto } = params
  if ((await descriptorDigest(descriptors, { crypto })) !== expectedDescriptorDigest) {
    throw new VaultTampered('Vault factor descriptors differ from the trusted digest')
  }
}
