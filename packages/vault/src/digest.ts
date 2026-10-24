import { blake3 } from '@noble/hashes/blake3.js'
import { fromUTF, toB64U } from '@sozai/codec'

import { VaultTampered } from './errors.js'
import type { FactorDescriptor } from './factors.js'

function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) ?? 'null'
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonicalJSON).join(',')}]`
  }

  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => {
    return left < right ? -1 : left > right ? 1 : 0
  })

  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJSON(item)}`).join(',')}}`
}

export function digestParts(parts: Array<string>): string {
  const framed = parts.map((part) => `${part.length}:${part}`).join('')

  return toB64U(blake3(fromUTF(framed), { dkLen: 32 }))
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

export function vaultKeyDigest(key: VaultKeyDigestInput): string {
  return digestParts([key.ownerDID, String(key.suite), String(key.version), key.state])
}

export function vaultWrappingDigest(wrapping: VaultWrappingDigestInput): string {
  return digestParts([
    wrapping.wrappingID,

    wrapping.recipientDID ?? '',
    wrapping.iv,
    wrapping.wrappedKey,
    canonicalJSON(wrapping.factors),
  ])
}

export function vaultEntriesDigest(entries: ReadonlyArray<VaultEntryDigestInput>): string {
  const ordered = [...entries].sort((left, right) => {
    return left.entryID < right.entryID ? -1 : left.entryID > right.entryID ? 1 : 0
  })

  return digestParts(
    ordered.flatMap((entry) => [entry.entryID, entry.iv, entry.ciphertext, entry.hlc]),
  )
}

export function vaultEntryDigest(entry: VaultEntryDigestInput): string {
  return vaultEntriesDigest([entry])
}

/** Same canonical descriptor encoding and length framing as the wrapping digest. */
export function descriptorDigest(descriptors: Array<FactorDescriptor>): string {
  return digestParts([canonicalJSON(descriptors)])
}

export function checkDescriptorDigest(params: {
  descriptors: Array<FactorDescriptor>
  expectedDescriptorDigest: string
}): void {
  if (descriptorDigest(params.descriptors) !== params.expectedDescriptorDigest) {
    throw new VaultTampered('Vault factor descriptors differ from the trusted digest')
  }
}
