import type { Kysely } from '@hozon/db'
import { withKeyLocks, withStoreTransaction } from '@hozon/db'
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
import type { VaultRecordsTables, VaultRecordTable } from './record-tables.js'
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

const boundAdapters = new WeakMap<RecordStoreAdapter, Bound>()
const acceptedKinds = new WeakMap<VaultStoreAPI, string>()

function supported(type: string): boolean {
  return (VAULT_RECORD_TYPES as ReadonlyArray<string>).includes(type)
}

function json(value: unknown): unknown {
  return typeof value === 'string' ? JSON.parse(value) : value
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

  for (const row of rows) {
    let value: CheckedRecord | null

    try {
      value = await checked(row, bound)
    } catch (error) {
      failure ??= error
      continue
    }

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
      const result = new Map<string, RecordDecision>()
      const addresses = [...wanted.values()]

      for (let start = 0; start < addresses.length; start += 160) {
        const chunk = addresses.slice(start, start + 160)
        const rows = await withStoreTransaction(db, async (tx) => {
          return tx
            .selectFrom('vault_records')
            .selectAll()
            .where((eb) => {
              return eb.or(
                chunk.map((key) => {
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
        const groups = new Map<string, Array<VaultRecordTable>>()

        for (const row of rows) {
          const key = recordKeyText(row)
          const group = groups.get(key) ?? []

          group.push(row)
          groups.set(key, group)
        }

        for (const [key, rows] of groups) {
          const value = await decision(rows, bound)

          if (value !== null) result.set(key, value)
        }
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
      const groups = new Map<string, Array<VaultRecordTable>>()

      for (const row of rows) {
        const key = recordKeyText(row)
        const group = groups.get(key) ?? []

        group.push(row)
        groups.set(key, group)
      }

      const result: Array<RecordDecision> = []

      for (const rows of groups.values()) {
        try {
          const value = await decision(rows, bound)

          if (value !== null) result.push(value)
        } catch (error) {
          if (!(error instanceof VaultRecordRowError)) throw error

          const row = rows[0]

          if (row !== undefined) bound.params.onCorruptRow?.({ type: row.type, id: row.id, error })
        }
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
      let keepHash = record.opHash

      for (const row of previousRows) {
        const prior = await checked(row, bound)

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
        for (const row of previousRows) {
          const prior = await checked(row, bound)

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
      const result: Array<SignedRecord> = []

      for (const row of rows) {
        const value = await checked(row, bound)

        if (value === null) throw new VaultRecordRowError(row)

        result.push(value.copy)
      }

      return result
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

        const addresses: Array<KeyAddress> = []

        for (const record of request.records) {
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

          if (op !== null && typeof op.claim.meta.keyID === 'string')
            addresses.push({ ownerDID: record.owner, keyID: op.claim.meta.keyID })

          const old = await tx.get(record)

          for (const copy of old?.copies ?? []) {
            const prior = await verifySignedRecord(copy, params.opKind, params.methods)

            if (typeof prior?.claim.meta.keyID === 'string')
              addresses.push({ ownerDID: copy.owner, keyID: prior.claim.meta.keyID })
          }
        }

        if (expectedKey !== undefined) addresses.push(expectedKey)

        const observedEntry =
          expectedEntry === undefined ? undefined : await inner.store.getEntry(expectedEntry)

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

        for (const record of request.records) {
          const current = await tx.get(record)

          for (const copy of current?.copies ?? []) {
            const op = await verifySignedRecord(copy, params.opKind, params.methods)

            if (op !== null && !heldKeys.has(JSON.stringify([op.claim.owner, op.claim.meta.keyID])))
              throw new VaultWriteConflict()
          }
        }

        if (expectedEntry !== undefined) {
          const current = await inner.store.getEntry(expectedEntry)

          if (current?.keyID !== observedEntry?.keyID) throw new VaultWriteConflict()
        }

        if (expectedKey !== undefined) {
          const row = await inner.store.getKey(expectedKey)

          if ((row?.version ?? null) !== expectedKey.expectedVersion) throw new VaultWriteConflict()

          if (expectedKey.expectedBranches !== undefined) {
            const branches = await createVaultRecords({
              ...params,
              store: inner.store,
            }).listKeyBranches({ ...expectedKey, keyVersion: expectedKey.expectedVersion ?? 0 })
            const current = branches.map((branch) => branch.branchID).sort()
            const expected = [...expectedKey.expectedBranches].sort()

            if (JSON.stringify(current) !== JSON.stringify(expected)) throw new VaultWriteConflict()
          }
        }

        if (
          expectedEntry !== undefined &&
          ((await inner.store.getEntry(expectedEntry))?.hlc ?? null) !== expectedEntry.expectedHLC
        )
          throw new VaultWriteConflict()

        return apply(request.records, tx, request.transportContext)
      })
    },
    async listKeyBranches(address) {
      await assertDomain(bound)
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
        const result: Array<VaultKeyBranch> = []

        for (const row of rows) {
          const op = await verifyRecordOp(row.op_jwt, params.opKind, params.methods)

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

          result.push({ branchID: row.branch_id, introducingOp: op })
        }

        return result
      })
    },
    async listWrappingsWithBranch(address) {
      await assertDomain(bound)

      return params.store.listWrappings(address)
    },
    listRevocations: (address) => vaultRecordPortsFor(adapter).listRevocations(address),
    listEntryCandidates: (address) => candidates(address, address.keyVersion, false),
    listPriorEntryTombstones: (address) => candidates(address, address.beforeVersion, true),
  }

  return api
}
