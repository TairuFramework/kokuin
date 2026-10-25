import type { Kysely } from '@hozon/db'
import { chunk, withStoreTransaction } from '@hozon/db'
import type {
  RecordDecision,
  RecordKey,
  RecordStoreAdapter,
  SignedRecord,
  VerifiedRecordOp,
} from '@kokuin/records'
import {
  recordClaimDigest,
  recordKeyText,
  recordPayloadMatches,
  verifySignedRecord,
} from '@kokuin/records'
import { decodeVaultRecord, VAULT_RECORD_TYPES } from '@kokuin/vault'

import { PARAMETER_BUDGET } from './batch.js'
import type { VaultDatabase } from './record-context.js'
import type { VaultRecordsTables, VaultRecordTable } from './record-tables.js'
import type { VaultRecordsParams } from './records.js'
import { settleAll } from './settle.js'
import type { VaultStoreAPI } from './types.js'

export class VaultRecordRowError extends Error {
  #type: string
  #id: string
  constructor(key: RecordKey & { cause?: unknown }) {
    super(`Stored vault record ${key.type} ${key.id} is corrupt`, { cause: key.cause })
    this.name = 'VaultRecordRowError'
    this.#type = key.type
    this.#id = key.id
  }
  get type(): string {
    return this.#type
  }
  get id(): string {
    return this.#id
  }
}

export type CheckedRecord = {
  copy: SignedRecord
  op: VerifiedRecordOp
}

export type HeldLock = { release: () => void; task: Promise<void> }

export type Bound = VaultDatabase & {
  opKind: string
  params: VaultRecordsParams
  store: VaultStoreAPI
  locks?: Array<HeldLock>
  /** Set once the domain row matched this adapter's operation kind. */
  domainChecked?: boolean
}

// Keyed OR predicates per getMany statement, within SQLite's default bind limit.
export const GET_MANY_CHUNK = 160

export const boundAdapters = new WeakMap<RecordStoreAdapter, Bound>()
export const acceptedKinds = new WeakMap<VaultStoreAPI, string>()

export function supported(type: string): boolean {
  return (VAULT_RECORD_TYPES as ReadonlyArray<string>).includes(type)
}

export function json(value: unknown): unknown {
  return typeof value === 'string' ? JSON.parse(value) : value
}

export function groupRows(rows: Array<VaultRecordTable>): Map<string, Array<VaultRecordTable>> {
  const groups = new Map<string, Array<VaultRecordTable>>()

  for (const row of rows) {
    const key = recordKeyText(row)
    const group = groups.get(key) ?? []

    group.push(row)
    groups.set(key, group)
  }

  return groups
}

/** Deletes the named copies of one record, in statements of at most `PARAMETER_BUDGET` binds. */
export async function deleteCopies(
  db: Kysely<VaultRecordsTables>,
  key: RecordKey,
  opHashes: Array<string>,
): Promise<void> {
  await settleAll(
    // Three binds name the record. The rest name copies.
    chunk(opHashes, PARAMETER_BUDGET - 3).map((part) => {
      return db
        .deleteFrom('vault_records')
        .where('type', '=', key.type)
        .where('owner', '=', key.owner)
        .where('id', '=', key.id)
        .where('op_hash', 'in', part)
        .execute()
    }),
  )
}

export function whereKey(db: Kysely<VaultRecordsTables>, key: RecordKey) {
  return db
    .selectFrom('vault_records')
    .selectAll()
    .where('type', '=', key.type)
    .where('owner', '=', key.owner)
    .where('id', '=', key.id)
}

export async function assertDomain(bound: Bound): Promise<void> {
  // The domain row is written once, in its own committed transaction, and never changed. Once it
  // matches, it matches for the bound adapter's lifetime.
  if (bound.domainChecked === true) return

  const row = await withStoreTransaction(bound.db, (db) => {
    return db.selectFrom('vault_record_domain').selectAll().executeTakeFirst()
  })

  if (row === undefined)
    throw new Error('Initialise the vault operation kind outside caller transactions')

  if (row.op_kind !== bound.opKind)
    throw new TypeError('Vault records store belongs to another operation kind')

  bound.domainChecked = true
}

export async function checked(row: VaultRecordTable, bound: Bound): Promise<CheckedRecord | null> {
  const key = { type: row.type, owner: row.owner, id: row.id }

  try {
    if (row.deleted !== 0 && row.deleted !== 1) throw new Error('invalid deleted flag')

    const payload = row.payload === null ? null : Uint8Array.from(row.payload)

    if ((row.deleted === 1) !== (payload === null)) throw new Error('invalid payload liveness')

    const meta = json(row.meta)

    if (meta === null || typeof meta !== 'object' || Array.isArray(meta))
      throw new Error('invalid metadata')

    const copy = { ...key, hlc: row.hlc, opJWT: row.op_jwt, opHash: row.op_hash, payload }
    const op = await verifySignedRecord(copy, bound.opKind, bound.params.methods)

    if (op === null) return null

    if (
      !recordPayloadMatches(copy, op.claim) ||
      row.payload_digest !== op.claim.payloadDigest ||
      row.deleted !== Number(op.claim.deleted) ||
      recordClaimDigest({ ...op.claim, meta: meta as Record<string, unknown> }) !==
        recordClaimDigest(op.claim)
    )
      throw new Error('stored claim mismatch')

    if (!op.claim.deleted) decodeVaultRecord(copy, op.claim.meta)

    return { copy, op }
  } catch (cause) {
    // biome-ignore lint/style/useErrorCause: the constructor forwards cause
    throw new VaultRecordRowError({ ...key, cause })
  }
}

export async function decision(
  rows: Array<VaultRecordTable>,
  bound: Bound,
): Promise<RecordDecision | null> {
  const copies: Array<SignedRecord> = []
  let selected: { contentDigest: string; decisionHLC: string } | undefined
  let failure: unknown
  // Checks run together. Results are consumed in row order, as the sequential checks were.
  const results = await Promise.allSettled(rows.map((row) => checked(row, bound)))

  for (const result of results) {
    if (result.status === 'rejected') {
      failure ??= result.reason
      continue
    }

    const value = result.value

    if (value === null) continue

    const contentDigest = recordClaimDigest(value.op.claim)
    const decisionHLC =
      typeof value.op.claim.meta.version === 'string'
        ? value.op.claim.meta.version
        : value.op.claim.hlc

    if (
      selected !== undefined &&
      (selected.contentDigest !== contentDigest || selected.decisionHLC !== decisionHLC)
    )
      throw new VaultRecordRowError(value.copy)

    selected = { contentDigest, decisionHLC }
    copies.push(value.copy)
  }

  if (selected === undefined) {
    if (failure !== undefined) throw failure

    // Invalid signatures cannot make an existing decision appear absent.
    if (rows[0] !== undefined) throw new VaultRecordRowError(rows[0])

    return null
  }

  const first = copies[0]

  if (first === undefined) return null

  return {
    key: { type: first.type, owner: first.owner, id: first.id },
    ...selected,
    copies: copies.sort((a, b) => a.opHash.localeCompare(b.opHash)),
  }
}

export function values(record: SignedRecord, op: VerifiedRecordOp, bound: Bound): VaultRecordTable {
  return {
    type: record.type,
    owner: record.owner,
    id: record.id,
    hlc: record.hlc,
    op_jwt: record.opJWT,
    op_hash: record.opHash,
    payload:
      record.payload === null ? null : (bound.adapter.encodeBinary(record.payload) as Uint8Array),
    payload_digest: op.claim.payloadDigest,
    deleted: Number(op.claim.deleted),
    meta: bound.adapter.encodeJSON(op.claim.meta) as Record<string, unknown>,
  }
}
