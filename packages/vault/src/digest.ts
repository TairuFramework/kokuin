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

export type DigestPartsParams = { parts: Array<string> } & CryptoOptions

export async function digestParts({ parts, ...options }: DigestPartsParams): Promise<string> {
  const framed = parts.map((part) => `${part.length}:${part}`).join('')

  return toB64U(await (options.crypto ?? nobleCrypto).blake3({ input: fromUTF(framed), dkLen: 32 }))
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

export type VaultKeyDigestParams = { key: VaultKeyDigestInput } & CryptoOptions

export function vaultKeyDigest({ key, ...options }: VaultKeyDigestParams): Promise<string> {
  return digestParts({
    ...options,
    parts: [key.ownerDID, String(key.suite), String(key.version), key.state],
  })
}

export type VaultWrappingDigestParams = { wrapping: VaultWrappingDigestInput } & CryptoOptions

export function vaultWrappingDigest({
  wrapping,
  ...options
}: VaultWrappingDigestParams): Promise<string> {
  return digestParts({
    ...options,
    parts: [
      wrapping.wrappingID,
      wrapping.recipientDID ?? '',
      wrapping.iv,
      wrapping.wrappedKey,
      descriptorJSON(wrapping.factors),
    ],
  })
}

export type VaultEntriesDigestParams = {
  entries: ReadonlyArray<VaultEntryDigestInput>
} & CryptoOptions

export function vaultEntriesDigest({
  entries,
  ...options
}: VaultEntriesDigestParams): Promise<string> {
  const ordered = [...entries].sort((left, right) => {
    return left.entryID < right.entryID ? -1 : left.entryID > right.entryID ? 1 : 0
  })

  return digestParts({
    ...options,
    parts: ordered.flatMap((entry) => [entry.entryID, entry.iv, entry.ciphertext, entry.hlc]),
  })
}

export type VaultEntryDigestParams = { entry: VaultEntryDigestInput } & CryptoOptions

export function vaultEntryDigest({ entry, ...options }: VaultEntryDigestParams): Promise<string> {
  return vaultEntriesDigest({ ...options, entries: [entry] })
}

/** Same canonical descriptor encoding and length framing as the wrapping digest. */
export type DescriptorDigestParams = { descriptors: Array<FactorDescriptor> } & CryptoOptions

export function descriptorDigest({
  descriptors,
  ...options
}: DescriptorDigestParams): Promise<string> {
  return digestParts({ ...options, parts: [descriptorJSON(descriptors)] })
}

export async function checkDescriptorDigest(
  params: CryptoOptions & {
    descriptors: Array<FactorDescriptor>
    expectedDescriptorDigest: string
  },
): Promise<void> {
  const { descriptors, expectedDescriptorDigest, crypto } = params
  if ((await descriptorDigest({ descriptors, crypto })) !== expectedDescriptorDigest) {
    throw new VaultTampered({ message: 'Vault factor descriptors differ from the trusted digest' })
  }
}
