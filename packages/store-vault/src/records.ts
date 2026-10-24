import type { Kysely } from '@hozon/db'
import { chunk, withKeyLocks, withStoreTransaction } from '@hozon/db'
import type {
  ApplyRecordChunkParams,
  ApplyResult,
  RecordDecision,
  RecordKey,
  RecordStoreAdapter,
  SignedRecord,
  VerifiedRecordOp,
} from '@kokuin/records'
import {
  applyRecordChunk,
  getRecordDecisions,
  recordClaimDigest,
  recordKeyText,
  recordPayloadMatches,
  recordSignerKey,
  verifyRecordOp,
  verifySignedRecord,
} from '@kokuin/records'
import type { VaultRecordPorts, VaultRecordTypeParams } from '@kokuin/vault'
import {
  decodeVaultRecord,
  VAULT_RECORD_TYPES,
  vaultRecordMeta,
  vaultRecordTypes,
  vaultRevocationRecordID,
} from '@kokuin/vault'

import { getVaultStore } from './definition.js'
import type { VaultDatabase } from './record-context.js'
import {
  claimMode,
  VaultModeConflict,
  VaultWriteConflict,
  vaultDatabases,
} from './record-context.js'
import { getVaultRecordsStore } from './record-definition.js'
import type { VaultKeyBranchTable, VaultRecordsTables, VaultRecordTable } from './record-tables.js'
import { settleAll, settledValue } from './settle.js'
import type { EntryAddress, KeyAddress, VaultStoreAPI, WrappingRow } from './types.js'

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

export type VaultWritePreconditions = {
  key?: KeyAddress & { expectedVersion: number | null; expectedBranches?: ReadonlyArray<string> }
  entry?: EntryAddress & { expectedHLC: string | null }
}

export type VaultRecordsParams = Omit<VaultRecordTypeParams, 'portsFor'> & {
  store: VaultStoreAPI
  nowMS: () => number
  maxDriftMS: number
  receiveClock?: ApplyRecordChunkParams['receiveClock']
  onCorruptRow?: (info: { type: string; id: string; error: unknown }) => void
}

export type VaultKeyBranch = {
  branchID: string
  /** The `vault.key-branch` record that projected this branch. */
  branchRecordID: string
  introducingOp: VerifiedRecordOp
}

type CheckedRecord = {
  copy: SignedRecord
  op: VerifiedRecordOp
}

export type VaultRecords = {
  adapter: RecordStoreAdapter
  apply(records: ReadonlyArray<SignedRecord>, transportContext?: unknown): Promise<ApplyResult>
  write(params: {
    records: ReadonlyArray<SignedRecord>
    preconditions: VaultWritePreconditions
    transportContext?: unknown
  }): Promise<ApplyResult>
  listKeyBranches(address: KeyAddress & { keyVersion: number }): Promise<Array<VaultKeyBranch>>
  /**
   * Rewrites the key's branch projection from its stored, verified `vault.key-branch` records.
   * Writes only when the projection differs. Returns whether it did.
   */
  rebuildKeyBranches(address: KeyAddress): Promise<boolean>
  listWrappingsWithBranch(
    address: KeyAddress & { keyVersion?: number },
  ): Promise<Array<WrappingRow>>
  listEntryCandidates(address: KeyAddress & { keyVersion: number }): Promise<Array<SignedRecord>>
  listPriorEntryTombstones(
    address: KeyAddress & { beforeVersion: number },
  ): Promise<Array<SignedRecord>>
  listRevocations(address: KeyAddress): Promise<Array<string>>
}

type HeldLock = { release: () => void; task: Promise<void> }

type Bound = VaultDatabase & {
  opKind: string
  params: VaultRecordsParams
  store: VaultStoreAPI
  locks?: Array<HeldLock>
}

// Keyed OR predicates per getMany statement, within SQLite's default bind limit.
const GET_MANY_CHUNK = 160

const boundAdapters = new WeakMap<RecordStoreAdapter, Bound>()
const acceptedKinds = new WeakMap<VaultStoreAPI, string>()

function supported(type: string): boolean {
  return (VAULT_RECORD_TYPES as ReadonlyArray<string>).includes(type)
}

function json(value: unknown): unknown {
  return typeof value === 'string' ? JSON.parse(value) : value
}

function groupRows(rows: Array<VaultRecordTable>): Map<string, Array<VaultRecordTable>> {
  const groups = new Map<string, Array<VaultRecordTable>>()

  for (const row of rows) {
    const key = recordKeyText(row)
    const group = groups.get(key) ?? []

    group.push(row)
    groups.set(key, group)
  }

  return groups
}

function whereKey(db: Kysely<VaultRecordsTables>, key: RecordKey) {
  return db
    .selectFrom('vault_records')
    .selectAll()
    .where('type', '=', key.type)
    .where('owner', '=', key.owner)
    .where('id', '=', key.id)
}

async function assertDomain(bound: Bound): Promise<void> {
  const row = await withStoreTransaction(bound.db, (db) => {
    return db.selectFrom('vault_record_domain').selectAll().executeTakeFirst()
  })

  if (row === undefined)
    throw new Error('Initialise the vault operation kind outside caller transactions')

  if (row.op_kind !== bound.opKind)
    throw new TypeError('Vault records store belongs to another operation kind')
}

async function checked(row: VaultRecordTable, bound: Bound): Promise<CheckedRecord | null> {
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

async function decision(
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

function values(record: SignedRecord, op: VerifiedRecordOp, bound: Bound): VaultRecordTable {
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

async function projection(record: SignedRecord, op: VerifiedRecordOp, bound: Bound): Promise<void> {
  const { db, adapter } = bound
  const type = record.type
  const table =
    type === 'vault.key'
      ? 'vault_keys'
      : type === 'vault.entry'
        ? 'vault_entries'
        : type === 'vault.wrapping'
          ? 'vault_wrappings'
          : null

  if (table !== null) {
    const column =
      type === 'vault.key' ? 'key_id' : type === 'vault.entry' ? 'entry_id' : 'wrapping_id'
    const existing = await db
      .selectFrom(table)
      .select('mode')
      .where('owner_did', '=', record.owner)
      .where(column, '=', record.id)
      .executeTakeFirst()

    if (existing?.mode === 'local') throw new VaultModeConflict()

    await claimMode(db, record, 'replicated')

    if (record.payload === null) {
      await db
        .deleteFrom(table)
        .where('owner_did', '=', record.owner)
        .where(column, '=', record.id)
        .execute()

      return
    }
  }

  const decoded = decodeVaultRecord(record, op.claim.meta)

  switch (decoded.type) {
    case 'vault.key': {
      const row = {
        owner_did: decoded.owner,
        key_id: decoded.id,
        suite: decoded.payload.suite,
        version: decoded.meta.version,
        state: decoded.payload.state,
        mode: 'replicated' as const,
      }

      await db
        .insertInto('vault_keys')
        .values(row)
        .onConflict((oc) => oc.columns(['owner_did', 'key_id']).doUpdateSet(row))
        .execute()

      break
    }
    case 'vault.wrapping': {
      const row = {
        owner_did: decoded.owner,
        wrapping_id: decoded.id,
        key_id: decoded.meta.keyID,
        key_version: decoded.meta.keyVersion,
        descriptors: adapter.encodeJSON(
          decoded.payload.descriptors,
        ) as typeof decoded.payload.descriptors,
        descriptor_digest: decoded.payload.descriptorDigest,
        iv: adapter.encodeBinary(decoded.payload.iv) as Uint8Array,
        wrapped_key: adapter.encodeBinary(decoded.payload.wrappedKey) as Uint8Array,
        recipient_did: decoded.meta.recipient,
        provenance: decoded.meta.branchID as string,
        mode: 'replicated' as const,
      }

      await db
        .insertInto('vault_wrappings')
        .values(row)
        .onConflict((oc) => oc.columns(['owner_did', 'wrapping_id']).doUpdateSet(row))
        .execute()

      break
    }
    case 'vault.entry': {
      const row = {
        owner_did: decoded.owner,
        entry_id: decoded.id,
        key_id: decoded.meta.keyID,
        key_version: decoded.meta.keyVersion,
        kind: decoded.meta.kind as string,
        label: decoded.meta.label as string,
        attributes: adapter.encodeJSON(decoded.meta.attributes) as Record<string, string>,
        iv: adapter.encodeBinary(decoded.payload.iv) as Uint8Array,
        ciphertext: adapter.encodeBinary(decoded.payload.ciphertext) as Uint8Array,
        hlc: decoded.hlc,
        provenance: decoded.meta.branchID as string,
        mode: 'replicated' as const,
      }

      await db
        .insertInto('vault_entries')
        .values(row)
        .onConflict((oc) => oc.columns(['owner_did', 'entry_id']).doUpdateSet(row))
        .execute()

      break
    }
    case 'vault.key-branch': {
      const row = {
        owner_did: decoded.owner,
        key_id: decoded.meta.keyID,
        key_version: decoded.meta.keyVersion,
        record_id: decoded.id,
        branch_id: decoded.meta.branchID,
        op_jwt: decoded.payload.opJWT,
      }

      await db
        .insertInto('vault_key_branches')
        .values(row)
        .onConflict((oc) => oc.columns(['owner_did', 'record_id']).doUpdateSet(row))
        .execute()

      break
    }
    case 'vault.revocation':
      await db
        .insertInto('vault_revocations')
        .values({
          owner_did: decoded.owner,
          key_id: decoded.meta.keyID,
          recipient_did: decoded.meta.revokedDID,
        })
        .onConflict((oc) => oc.columns(['owner_did', 'key_id', 'recipient_did']).doNothing())
        .execute()
  }
}

/** Resolve effects only through an adapter bound to the apply transaction. */
export function vaultRecordPortsFor(store: RecordStoreAdapter): VaultRecordPorts {
  const bound =
    boundAdapters.get(store) ??
    boundAdapters.get(store.adapterForType?.('vault.entry') as RecordStoreAdapter)

  if (bound === undefined) throw new Error('Vault adapter is unavailable for effect ports')

  const { db } = bound

  return {
    async retainEntryCandidate(record) {
      if (!db.isTransaction) throw new Error('Candidate retention requires the apply transaction')

      const op = await verifySignedRecord(record, bound.opKind, bound.params.methods)

      if (
        op === null ||
        !recordPayloadMatches(record, op.claim) ||
        vaultRecordMeta('vault.entry', op.claim) === null
      )
        throw new Error('Invalid entry candidate')

      await db
        .insertInto('vault_entry_candidates')
        .values({
          ...values(record, op, bound),
          key_id: op.claim.meta.keyID as string,
          key_version: op.claim.meta.keyVersion as number,
          branch_id: (op.claim.meta.branchID as string) ?? '',
        })
        .onConflict((oc) => oc.columns(['type', 'owner', 'id', 'op_hash']).doNothing())
        .execute()
    },
    async listRevocations(address) {
      await assertDomain(bound)

      const rows = await withStoreTransaction(db, async (tx) => {
        return tx
          .selectFrom('vault_revocations')
          .select('recipient_did')
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .orderBy('recipient_did')
          .execute()
      })

      return rows.map((row) => row.recipient_did)
    },
    async dropRevokedWrappings(address) {
      if (!db.isTransaction) throw new Error('Wrapping suppression requires the apply transaction')

      const denied = new Set(
        (await this.listRevocations(address)).map((did) => {
          return vaultRevocationRecordID(address.keyID, did)
        }),
      )

      for (const row of await bound.store.listWrappings(address)) {
        const recipients = [
          row.recipientDID,
          ...row.descriptors.filter((d) => d.kind === 'did').map((d) => d.params.recipient),
        ]

        if (
          !recipients.some((recipient) => {
            return (
              typeof recipient === 'string' &&
              denied.has(vaultRevocationRecordID(address.keyID, recipient))
            )
          })
        )
          continue

        // Denial never deletes an unrelated local record.
        const held = await db
          .selectFrom('vault_wrappings')
          .select('mode')
          .where('owner_did', '=', row.ownerDID)
          .where('wrapping_id', '=', row.wrappingID)
          .executeTakeFirst()

        if (held?.mode === 'local') throw new VaultModeConflict()

        await db
          .deleteFrom('vault_wrappings')
          .where('owner_did', '=', row.ownerDID)
          .where('wrapping_id', '=', row.wrappingID)
          .execute()
      }
    },
  }
}

function makeAdapter(bound: Bound): RecordStoreAdapter {
  const { db } = bound
  const adapter: RecordStoreAdapter = {
    isTransaction: db.isTransaction,
    async transaction(fn) {
      return bound.context.provider.withTransaction(async (provider) => {
        const storage = await getVaultRecordsStore(provider)
        const innerBound: Bound = {
          ...bound,
          ...storage,
          store: await getVaultStore(provider),
          locks: [],
        }
        const inner = makeAdapter(innerBound)

        return withStoreTransaction(storage.db, async () => {
          await assertDomain(innerBound)
          try {
            return await fn(inner)
          } finally {
            for (const lock of [...(innerBound.locks ?? [])].reverse()) lock.release()
            await Promise.all((innerBound.locks ?? []).map((lock) => lock.task))
          }
        })
      })
    },
    async get(key) {
      await assertDomain(bound)

      if (!supported(key.type)) return null

      return withStoreTransaction(db, async (tx) => {
        return decision(await whereKey(tx, key).orderBy('op_hash').execute(), bound)
      })
    },
    async getMany(keys) {
      await assertDomain(bound)

      const wanted = new Map(
        keys.filter((key) => supported(key.type)).map((key) => [recordKeyText(key), key]),
      )
      const loadChunk = async (addresses: Array<RecordKey>): Promise<Array<VaultRecordTable>> => {
        return withStoreTransaction(db, async (tx) => {
          return tx
            .selectFrom('vault_records')
            .selectAll()
            .where((eb) => {
              return eb.or(
                addresses.map((key) => {
                  return eb.and([
                    eb('type', '=', key.type),
                    eb('owner', '=', key.owner),
                    eb('id', '=', key.id),
                  ])
                }),
              )
            })
            .orderBy('op_hash')
            .execute()
        })
      }
      const chunks = await settleAll(chunk(wanted.values(), GET_MANY_CHUNK).map(loadChunk))
      const groups = [...groupRows(chunks.flat())]
      const decisions = await settleAll(groups.map(([, rows]) => decision(rows, bound)))
      const result = new Map<string, RecordDecision>()

      for (const [index, [key]] of groups.entries()) {
        const value = decisions[index]

        if (value !== null && value !== undefined) result.set(key, value)
      }

      return result
    },
    async list(types) {
      await assertDomain(bound)

      const selected = [...new Set(types.filter(supported))]

      if (selected.length === 0) return []

      const rows = await withStoreTransaction(db, async (tx) => {
        return tx
          .selectFrom('vault_records')
          .selectAll()
          .where('type', 'in', selected)
          .orderBy('type')
          .orderBy('owner')
          .orderBy('id')
          .orderBy('op_hash')
          .execute()
      })
      const groups = [...groupRows(rows).values()]
      const decisions = await Promise.allSettled(groups.map((group) => decision(group, bound)))
      const result: Array<RecordDecision> = []

      // Callbacks and non-row failures keep group order.
      for (const [index, outcome] of decisions.entries()) {
        if (outcome.status === 'fulfilled') {
          if (outcome.value !== null) result.push(outcome.value)

          continue
        }

        const error: unknown = outcome.reason

        if (!(error instanceof VaultRecordRowError)) throw error

        const row = groups[index]?.[0]

        if (row !== undefined) bound.params.onCorruptRow?.({ type: row.type, id: row.id, error })
      }

      return result
    },
    async lock(keys) {
      if (!bound.context.provider.isTransactionBound || bound.locks === undefined)
        throw new Error('Record locks require an adapter transaction')

      if (keys.some((key) => key.type !== 'vault.key'))
        throw new TypeError('Unknown vault lock namespace')

      const entered = Promise.withResolvers<void>()
      const released = Promise.withResolvers<void>()
      // Keep hozon's queue held through authoritative reads and all apply effects.
      const task = withKeyLocks(
        bound.context.provider,
        'vault_keys',
        keys.map((key) => [key.key]),
        async (provider) => {
          bound.context = { ...bound.context, provider }
          bound.store = await getVaultStore(provider)
          entered.resolve()
          await released.promise
        },
      )

      bound.locks.push({ release: () => released.resolve(), task })
      await Promise.race([entered.promise, task])
    },
    async putCopy(record) {
      if (!db.isTransaction) throw new Error('Copy persistence requires the apply transaction')

      await assertDomain(bound)

      const op = await verifySignedRecord(record, bound.opKind, bound.params.methods)

      if (op === null || !supported(record.type) || !recordPayloadMatches(record, op.claim))
        throw new Error('Invalid vault record copy')

      const type = record.type as (typeof VAULT_RECORD_TYPES)[number]

      if (vaultRecordMeta(type, op.claim) === null) throw new Error('Invalid vault record metadata')

      const previousRows = await whereKey(db, record).orderBy('op_hash').execute()
      const previous = await decision(previousRows, bound)
      const contentDigest = recordClaimDigest(op.claim)
      const decisionHLC =
        typeof op.claim.meta.version === 'string' ? op.claim.meta.version : op.claim.hlc
      const same = previous?.contentDigest === contentDigest && previous.decisionHLC === decisionHLC
      const incomingSigner = recordSignerKey(op.issuer, record.opJWT)
      // One check per prior row, shared by both passes. The first failure in row order wins.
      const priors = await settleAll(previousRows.map((row) => checked(row, bound)))
      let keepHash = record.opHash

      for (const [index, row] of previousRows.entries()) {
        const prior = priors[index] ?? null

        if (
          same &&
          prior !== null &&
          recordSignerKey(prior.op.issuer, prior.copy.opJWT) === incomingSigner &&
          row.op_hash < keepHash
        )
          keepHash = row.op_hash
      }

      if (!same) {
        await db
          .deleteFrom('vault_records')
          .where('type', '=', record.type)
          .where('owner', '=', record.owner)
          .where('id', '=', record.id)
          .execute()

        await projection(record, op, bound)
      } else {
        for (const [index, row] of previousRows.entries()) {
          const prior = priors[index] ?? null

          if (
            prior === null ||
            (recordSignerKey(prior.op.issuer, prior.copy.opJWT) === incomingSigner &&
              row.op_hash !== keepHash)
          )
            await db
              .deleteFrom('vault_records')
              .where('type', '=', record.type)
              .where('owner', '=', record.owner)
              .where('id', '=', record.id)
              .where('op_hash', '=', row.op_hash)
              .execute()
        }
      }

      if (keepHash === record.opHash)
        await db
          .insertInto('vault_records')
          .values(values(record, op, bound))
          .onConflict((oc) => oc.columns(['type', 'owner', 'id', 'op_hash']).doNothing())
          .execute()

      await claimMode(db, record, 'replicated')
      await db
        .updateTable('vault_decisions')
        .set({ content_digest: contentDigest, decision_hlc: decisionHLC })
        .where('type', '=', record.type)
        .where('owner', '=', record.owner)
        .where('id', '=', record.id)
        .execute()
    },
    async pruneCopy(key, signerDID) {
      if (!db.isTransaction) throw new Error('Copy pruning requires the apply transaction')

      const current = await adapter.get(key)

      if (current === null) return

      const verified = await Promise.all(
        current.copies.map(async (copy) => {
          return {
            copy,
            op: await verifySignedRecord(copy, bound.opKind, bound.params.methods),
          }
        }),
      )

      if (!verified.some(({ op }) => op !== null && op.issuer !== signerDID)) return

      for (const { copy, op } of verified)
        if (op?.issuer === signerDID)
          await db
            .deleteFrom('vault_records')
            .where('type', '=', key.type)
            .where('owner', '=', key.owner)
            .where('id', '=', key.id)
            .where('op_hash', '=', copy.opHash)
            .execute()
    },
  }

  boundAdapters.set(adapter, bound)

  return adapter
}

export function createVaultRecords(params: VaultRecordsParams): VaultRecords {
  if (typeof params.opKind !== 'string' || params.opKind.length === 0)
    throw new TypeError('An explicit operation kind is required')

  const storage = vaultDatabases.get(params.store)

  if (storage === undefined || !storage.context.provider.hasStore('vault-records'))
    throw new Error('Register the optional vault records store first')

  const existingKind = acceptedKinds.get(params.store)

  if (existingKind !== undefined && existingKind !== params.opKind)
    throw new TypeError('Vault records store belongs to another operation kind')

  acceptedKinds.set(params.store, params.opKind)

  const bound: Bound = { ...storage, params, opKind: params.opKind, store: params.store }
  const adapter = makeAdapter(bound)
  const types = vaultRecordTypes({ ...params, portsFor: vaultRecordPortsFor })
  const apply = (
    records: ReadonlyArray<SignedRecord>,
    store: RecordStoreAdapter,
    transportContext?: unknown,
  ) => {
    return applyRecordChunk({
      records,
      store,
      types,
      opKind: params.opKind,
      nowMS: params.nowMS(),
      maxDriftMS: params.maxDriftMS,
      receiveClock: params.receiveClock ?? (() => {}),
      methods: params.methods,
      transportContext,
      resolveController: async () => null,
      verifyCapability: async () => false,
    })
  }
  const candidates = async (
    address: KeyAddress,
    version: number,
    prior: boolean,
  ): Promise<Array<SignedRecord>> => {
    await assertDomain(bound)

    return withStoreTransaction(bound.db, async (tx) => {
      let query = tx
        .selectFrom('vault_entry_candidates')
        .selectAll()
        .where('owner', '=', address.ownerDID)
        .where('key_id', '=', address.keyID)

      query = prior
        ? query.where('key_version', '<', version).where('deleted', '=', 1)
        : query.where('key_version', '=', version)

      const rows = await query.orderBy('id').orderBy('op_hash').execute()

      return settleAll(
        rows.map(async (row) => {
          const value = await checked(row, bound)

          if (value === null) throw new VaultRecordRowError(row)

          return value.copy
        }),
      )
    })
  }
  const api: VaultRecords = {
    adapter,
    apply: (records, transportContext) => apply(records, adapter, transportContext),
    async write(request) {
      if (request.preconditions === undefined)
        throw new TypeError('Signed writes require explicit preconditions')

      return adapter.transaction(async (tx) => {
        const inner = boundAdapters.get(tx)

        if (inner === undefined) throw new Error('Missing transaction adapter')

        const expectedKey = request.preconditions.key
        const expectedEntry = request.preconditions.entry

        if (expectedKey === undefined && expectedEntry === undefined)
          throw new TypeError('Signed writes require a key or entry precondition')

        // The address precondition reads nothing, so it runs before any store read, as it did.
        const ops = await settleAll(
          request.records.map(async (record) => {
            const op = await verifySignedRecord(record, params.opKind, params.methods)

            if (
              op !== null &&
              !(
                (expectedKey !== undefined &&
                  expectedKey.ownerDID === op.claim.owner &&
                  expectedKey.keyID === op.claim.meta.keyID) ||
                (expectedEntry !== undefined &&
                  record.type === 'vault.entry' &&
                  expectedEntry.ownerDID === record.owner &&
                  expectedEntry.entryID === record.id)
              )
            )
              throw new TypeError('Every signed output requires an address precondition')

            return op
          }),
        )
        const [old, observedEntry] = await settleAll([
          getRecordDecisions(tx, request.records),
          expectedEntry === undefined
            ? Promise.resolve(undefined)
            : inner.store.getEntry(expectedEntry),
        ])
        const recordAddresses = await settleAll(
          request.records.map(async (record, position) => {
            const op = ops[position] ?? null
            const found: Array<KeyAddress> = []

            if (op !== null && typeof op.claim.meta.keyID === 'string')
              found.push({ ownerDID: record.owner, keyID: op.claim.meta.keyID })

            const copies = old.get(recordKeyText(record))?.copies ?? []
            const priors = await settleAll(
              copies.map((copy) => verifySignedRecord(copy, params.opKind, params.methods)),
            )

            for (const [index, prior] of priors.entries()) {
              const copy = copies[index]

              if (copy !== undefined && typeof prior?.claim.meta.keyID === 'string')
                found.push({ ownerDID: copy.owner, keyID: prior.claim.meta.keyID })
            }

            return found
          }),
        )
        const addresses: Array<KeyAddress> = recordAddresses.flat()

        if (expectedKey !== undefined) addresses.push(expectedKey)

        if (observedEntry !== undefined) addresses.push(observedEntry)

        await tx.lock?.(
          addresses.map((address) => {
            return {
              type: 'vault.key',
              key: JSON.stringify([address.ownerDID, address.keyID]),
            }
          }),
        )

        const heldKeys = new Set(
          addresses.map((address) => JSON.stringify([address.ownerDID, address.keyID])),
        )
        // Authoritative reads follow the lock. They are independent of each other.
        const keyCheck = async (): Promise<boolean> => {
          if (expectedKey === undefined) return true

          const row = await inner.store.getKey(expectedKey)

          if ((row?.version ?? null) !== expectedKey.expectedVersion) return false

          if (expectedKey.expectedBranches === undefined) return true

          const branches = await createVaultRecords({
            ...params,
            store: inner.store,
          }).listKeyBranches({ ...expectedKey, keyVersion: expectedKey.expectedVersion ?? 0 })
          const current = branches.map((branch) => branch.branchID).sort()
          const expected = [...expectedKey.expectedBranches].sort()

          return JSON.stringify(current) === JSON.stringify(expected)
        }
        // All three run together. Results are checked in the old order: held copies, entry key,
        // key version and branches, entry HLC.
        const [currentRead, entryRead, keyRead] = await Promise.allSettled([
          getRecordDecisions(tx, request.records),
          expectedEntry === undefined
            ? Promise.resolve(undefined)
            : inner.store.getEntry(expectedEntry),
          keyCheck(),
        ])
        const current = settledValue(currentRead)
        const currentOps = await settleAll(
          request.records.flatMap((record) => {
            return (current.get(recordKeyText(record))?.copies ?? []).map((copy) => {
              return verifySignedRecord(copy, params.opKind, params.methods)
            })
          }),
        )

        for (const op of currentOps)
          if (op !== null && !heldKeys.has(JSON.stringify([op.claim.owner, op.claim.meta.keyID])))
            throw new VaultWriteConflict()

        const currentEntry = settledValue(entryRead)

        if (expectedEntry !== undefined && currentEntry?.keyID !== observedEntry?.keyID)
          throw new VaultWriteConflict()

        if (!settledValue(keyRead)) throw new VaultWriteConflict()

        if (
          expectedEntry !== undefined &&
          (currentEntry?.hlc ?? null) !== expectedEntry.expectedHLC
        )
          throw new VaultWriteConflict()

        return apply(request.records, tx, request.transportContext)
      })
    },
    async listKeyBranches(address) {
      await assertDomain(bound)

      return withStoreTransaction(bound.db, async (tx) => {
        const rows = await tx
          .selectFrom('vault_key_branches')
          .selectAll()
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .where('key_version', '=', address.keyVersion)
          .orderBy('branch_id')
          .execute()
        const ops = await settleAll(
          rows.map((row) => verifyRecordOp(row.op_jwt, params.opKind, params.methods)),
        )
        const result: Array<VaultKeyBranch> = []

        for (const [index, row] of rows.entries()) {
          const op = ops[index] ?? null

          if (
            op === null ||
            op.claim.owner !== address.ownerDID ||
            op.claim.id !== address.keyID ||
            op.claim.meta.version !== address.keyVersion ||
            row.branch_id !== `${op.claim.hlc}:${op.opHash}`
          )
            throw new VaultRecordRowError({
              type: 'vault.key-branch',
              owner: row.owner_did,
              id: row.record_id,
            })

          result.push({ branchID: row.branch_id, branchRecordID: row.record_id, introducingOp: op })
        }

        return result
      })
    },
    async listWrappingsWithBranch(address) {
      await assertDomain(bound)

      return params.store.listWrappings(address)
    },
    async rebuildKeyBranches(address) {
      await assertDomain(bound)

      const decisions = await adapter.list(['vault.key-branch'])
      const candidates = decisions.flatMap((decision) => {
        const record = decision.copies[0]

        return record !== undefined && record.owner === address.ownerDID ? [record] : []
      })
      const ops = await settleAll(
        candidates.map((record) => verifySignedRecord(record, params.opKind, params.methods)),
      )
      const rows: Array<VaultKeyBranchTable> = []

      for (const [index, record] of candidates.entries()) {
        const op = ops[index] ?? null

        if (op === null || op.claim.meta.keyID !== address.keyID) continue

        const decoded = decodeVaultRecord(record, op.claim.meta)

        if (decoded.type !== 'vault.key-branch') continue

        rows.push({
          owner_did: decoded.owner,
          key_id: decoded.meta.keyID,
          key_version: decoded.meta.keyVersion,
          record_id: decoded.id,
          branch_id: decoded.meta.branchID,
          op_jwt: decoded.payload.opJWT,
        })
      }

      const text = (list: Array<VaultKeyBranchTable>) => {
        return JSON.stringify(
          list
            .map((row) => [row.record_id, row.key_version, row.branch_id, row.op_jwt])
            .sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
        )
      }

      return withStoreTransaction(bound.db, async (tx) => {
        const held = await tx
          .selectFrom('vault_key_branches')
          .selectAll()
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .execute()

        if (text(held) === text(rows)) return false

        await tx
          .deleteFrom('vault_key_branches')
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .execute()

        for (const row of rows)
          await tx
            .insertInto('vault_key_branches')
            .values(row)
            .onConflict((oc) => oc.columns(['owner_did', 'record_id']).doUpdateSet(row))
            .execute()

        return true
      })
    },
    listRevocations: (address) => vaultRecordPortsFor(adapter).listRevocations(address),
    listEntryCandidates: (address) => candidates(address, address.keyVersion, false),
    listPriorEntryTombstones: (address) => candidates(address, address.beforeVersion, true),
  }

  return api
}
