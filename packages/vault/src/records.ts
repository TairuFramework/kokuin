import type { RecordClaim, SignedRecord } from '@kokuin/records'
import { parseCanonicalHLC, recordPayloadDigest } from '@kokuin/records'
import { normalizeDID } from '@kokuin/token'
import { canonicalStringify, fromB64U, fromUTF, toB64U, toUTF } from '@sozai/codec'

import type { FactorDescriptor } from './factors.js'
import { createVaultKeyID } from './id.js'
import type { EncryptEntryResult, WrapResult } from './suite.js'

export const VAULT_OP_KIND = 'kokuin/vault-op/v1'
export const VAULT_RECORD_TYPES = [
  'vault.key',
  'vault.key-branch',
  'vault.wrapping',
  'vault.entry',
  'vault.revocation',
] as const

export type VaultRecordType = (typeof VAULT_RECORD_TYPES)[number]

export type VaultRecordPayloads = {
  'vault.key': { suite: number; state: 'active' | 'retired' }
  'vault.key-branch': {
    authorDID: string
    hlc: string
    opJWT: string
    opHash: string
    suite: number
  }
  'vault.wrapping': WrapResult
  'vault.entry': EncryptEntryResult
  'vault.revocation': Record<string, never>
}

export type VaultEntryMetadata = { kind: string; label: string; attributes: Record<string, string> }

type BranchReference = { branchID: string; branchRecordID: string }

export type VaultRecordMetas = {
  'vault.key': {
    keyID: string
    keyUnique: string
    version: number
    state: 'active' | 'retired' | 'deleted'
    consumer: unknown
  }
  'vault.key-branch': { keyID: string; keyVersion: number; branchID: string; consumer: unknown }
  'vault.wrapping': {
    keyID: string
    keyVersion: number
    recipient: string | null
    consumer: unknown
  } & Partial<BranchReference>
  'vault.entry': {
    keyID: string
    keyVersion: number
    contentHLC: string
    consumer: unknown
  } & Partial<BranchReference> &
    Partial<VaultEntryMetadata>
  'vault.revocation': { keyID: string; revokedDID: string; consumer: unknown }
}

export type DecodedVaultRecord = {
  [Type in VaultRecordType]: {
    type: Type
    id: string
    owner: string
    hlc: string
    meta: VaultRecordMetas[Type]
    payload: VaultRecordPayloads[Type]
  }
}[VaultRecordType]

export class VaultRecordPayloadError extends Error {
  #type: string
  #id: string
  constructor(params: { type: string; id: string; reason: string; cause?: unknown }) {
    const { type, id, reason, cause } = params

    super(`Vault record ${type} ${id}: ${reason}`, { cause })
    this.name = 'VaultRecordPayloadError'
    this.#type = type
    this.#id = id
  }
  get type(): string {
    return this.#type
  }
  get id(): string {
    return this.#id
  }
}

export function vaultRevocationRecordID(keyID: string, recipientDID: string): string {
  return `${keyID.length}:${keyID}/${normalizeDID(recipientDID)}`
}

function plain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false

  const prototype = Object.getPrototypeOf(value)

  return prototype === Object.prototype || prototype === null
}

const text = (value: unknown): value is string => typeof value === 'string' && value !== ''
const count = (value: unknown): value is number => {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function did(value: unknown): value is string {
  try {
    return typeof value === 'string' && normalizeDID(value) === value
  } catch {
    return false
  }
}

function base64(value: unknown, length: number): value is string {
  try {
    return (
      typeof value === 'string' &&
      fromB64U(value).length === length &&
      toB64U(fromB64U(value)) === value
    )
  } catch {
    return false
  }
}

function keyID(value: unknown): value is string {
  if (typeof value !== 'string' || !/^k[0-9a-z]+$/.test(value) || value.length > 57) return false

  let integer = 0n

  for (const character of value.slice(1))
    integer = integer * 36n + BigInt(Number.parseInt(character, 36))

  const hex = integer.toString(16)

  return hex.length === 72 && hex.startsWith('b6011f20') && `k${integer.toString(36)}` === value
}

function shape(
  value: Record<string, unknown>,
  required: Record<string, (v: unknown) => boolean>,
  optional: Record<string, (v: unknown) => boolean> = {},
): boolean {
  return (
    Object.keys(value).every((k) => Object.hasOwn(required, k) || Object.hasOwn(optional, k)) &&
    Object.entries(required).every(([k, check]) => Object.hasOwn(value, k) && check(value[k])) &&
    Object.entries(optional).every(([k, check]) => !Object.hasOwn(value, k) || check(value[k]))
  )
}

const consumer = { consumer: (_value: unknown) => true }
const branch = { branchID: text, branchRecordID: (v: unknown) => base64(v, 32) }
const entryMetadata = {
  kind: text,
  label: (v: unknown) => typeof v === 'string',
  attributes: (v: unknown) => {
    return plain(v) && Object.values(v).every((value) => typeof value === 'string')
  },
}

/** Structural metadata only. Consumer evidence is checked by the injected validator. */
export function vaultRecordMeta<Type extends VaultRecordType>(
  type: Type,
  claim: RecordClaim,
): VaultRecordMetas[Type] | null {
  if (claim.type !== type || !plain(claim.meta)) return null

  const m = claim.meta
  let valid: boolean

  switch (type) {
    case 'vault.key':
      valid =
        shape(m, {
          keyID,
          keyUnique: (v) => base64(v, 16),
          version: count,
          state: (v) => (claim.deleted ? v === 'deleted' : v === 'active' || v === 'retired'),
          ...consumer,
        }) &&
        m.keyID === claim.id &&
        createVaultKeyID(claim.owner, fromB64U(m.keyUnique as string)) === claim.id
      break
    case 'vault.key-branch':
      valid = !claim.deleted && shape(m, { keyID, keyVersion: count, branchID: text, ...consumer })
      break
    case 'vault.wrapping':
      valid =
        shape(
          m,
          {
            keyID,
            keyVersion: count,
            recipient: (v) => v === null || did(v),
            ...consumer,
            ...(claim.deleted ? {} : branch),
          },
          claim.deleted ? branch : {},
        ) && Object.hasOwn(m, 'branchID') === Object.hasOwn(m, 'branchRecordID')
      break
    case 'vault.entry':
      valid =
        shape(
          m,
          {
            keyID,
            keyVersion: count,
            contentHLC: (v) => typeof v === 'string' && parseCanonicalHLC(v) !== null,
            ...consumer,
            ...(claim.deleted ? {} : { ...branch, ...entryMetadata }),
          },
          claim.deleted ? { ...branch, ...entryMetadata } : {},
        ) && Object.hasOwn(m, 'branchID') === Object.hasOwn(m, 'branchRecordID')
      break
    case 'vault.revocation':
      valid =
        !claim.deleted &&
        shape(m, { keyID, revokedDID: did, ...consumer }) &&
        claim.id === vaultRevocationRecordID(m.keyID as string, m.revokedDID as string)
      break
    default:
      return null
  }

  return valid ? (m as VaultRecordMetas[Type]) : null
}

function wire(type: VaultRecordType, payload: VaultRecordPayloads[VaultRecordType]): unknown {
  if (type === 'vault.wrapping') {
    const { descriptors, descriptorDigest, iv, wrappedKey } = payload as WrapResult

    return { descriptors, descriptorDigest, iv: toB64U(iv), wrappedKey: toB64U(wrappedKey) }
  }

  if (type === 'vault.entry') {
    const { iv, ciphertext } = payload as EncryptEntryResult

    return { iv: toB64U(iv), ciphertext: toB64U(ciphertext) }
  }

  return payload
}

/** Canonical JSON with binary fields encoded as unpadded base64url. */
export function encodeVaultRecordPayload<Type extends VaultRecordType>(
  type: Type,
  payload: VaultRecordPayloads[Type],
): Uint8Array {
  return fromUTF(canonicalStringify(wire(type, payload)))
}

function bytes(value: unknown): Uint8Array {
  if (typeof value !== 'string') throw new Error('binary field is not a string')

  const decoded = fromB64U(value)

  if (toB64U(decoded) !== value) throw new Error('binary field is not canonical base64url')

  return decoded
}

const anything = (_value: unknown) => true

function payloadOf(type: VaultRecordType, data: Uint8Array): VaultRecordPayloads[VaultRecordType] {
  const parsed: unknown = JSON.parse(toUTF(data))

  if (!plain(parsed)) throw new Error('payload is not an object')

  const canonical = fromUTF(canonicalStringify(parsed))

  if (canonical.length !== data.length || canonical.some((v, i) => v !== data[i]))
    throw new Error('payload is not canonical JSON')

  switch (type) {
    case 'vault.key':
      if (!shape(parsed, { suite: count, state: (v) => v === 'active' || v === 'retired' }))
        throw new Error('key payload fields')
      return parsed as VaultRecordPayloads['vault.key']
    case 'vault.key-branch':
      if (
        !shape(parsed, {
          authorDID: did,
          hlc: text,
          opJWT: text,
          opHash: (v) => base64(v, 32),
          suite: count,
        })
      )
        throw new Error('branch payload fields')
      return parsed as VaultRecordPayloads['vault.key-branch']
    case 'vault.wrapping': {
      if (
        !shape(parsed, {
          descriptors: (v) => {
            return (
              Array.isArray(v) &&
              v.every((factor) => plain(factor) && shape(factor, { kind: text, params: plain }))
            )
          },
          descriptorDigest: (v) => base64(v, 32),
          iv: anything,
          wrappedKey: anything,
        })
      )
        throw new Error('wrapping payload fields')

      return {
        descriptors: parsed.descriptors as Array<FactorDescriptor>,
        descriptorDigest: parsed.descriptorDigest as string,
        iv: bytes(parsed.iv),
        wrappedKey: bytes(parsed.wrappedKey),
      }
    }
    case 'vault.entry':
      if (!shape(parsed, { iv: anything, ciphertext: anything }))
        throw new Error('entry payload fields')
      return { iv: bytes(parsed.iv), ciphertext: bytes(parsed.ciphertext) }
    case 'vault.revocation':
      if (!shape(parsed, {})) throw new Error('revocation payload fields')
      return {}
  }
}

/** Pure codec. Signature and payload-digest verification belong to the caller. */
export function decodeVaultRecord(
  record: Pick<SignedRecord, 'type' | 'id' | 'owner' | 'hlc' | 'payload'>,
  meta: Record<string, unknown>,
): DecodedVaultRecord {
  const { type, id, owner, hlc, payload } = record

  try {
    if (!(VAULT_RECORD_TYPES as ReadonlyArray<string>).includes(type))
      throw new Error('unknown record type')

    if (payload === null) throw new Error('a tombstone has no payload')

    const recordType = type as VaultRecordType
    const decodedMeta = vaultRecordMeta(recordType, {
      type,
      id,
      owner,
      hlc,
      meta,
      deleted: false,
      payloadDigest: recordPayloadDigest(payload),
    })

    if (decodedMeta === null) throw new Error('record metadata')

    if (type === 'vault.key-branch' && id !== recordPayloadDigest(payload))
      throw new Error('record id is not the payload digest')

    return {
      type,
      id,
      owner,
      hlc,
      meta: decodedMeta,
      payload: payloadOf(recordType, payload),
    } as DecodedVaultRecord
  } catch (cause) {
    // biome-ignore lint/style/useErrorCause: the constructor carries cause in its parameter object
    throw new VaultRecordPayloadError({
      type,
      id,
      reason: cause instanceof Error ? cause.message : 'invalid record',
      cause,
    })
  }
}
