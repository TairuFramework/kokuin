import { withStoreTransaction } from '@hozon/db'
import type {
  ApplyRecordChunkParams,
  ApplyResult,
  RecordStoreAdapter,
  SignedRecord,
  VerifiedRecordOp,
} from '@kokuin/records'
import {
  applyRecordChunk,
  getRecordDecisions,
  recordKeyText,
  verifyRecordOp,
  verifySignedRecord,
} from '@kokuin/records'
import type { VaultRecordTypeParams } from '@kokuin/vault'
import { decodeVaultRecord, vaultRecordTypes } from '@kokuin/vault'

import { KEY_BRANCH_COLUMNS, statementChunks, upsertKeyBranches } from './batch.js'
import { VaultWriteConflict, vaultDatabases } from './record-context.js'
import type { VaultKeyBranchTable } from './record-tables.js'
import { makeAdapter } from './records-adapter.js'
import { vaultRecordPortsFor } from './records-ports.js'
import type { Bound } from './records-rows.js'
import {
  acceptedKinds,
  assertDomain,
  boundAdapters,
  checked,
  VaultRecordRowError,
} from './records-rows.js'
import { settleAll, settledValue } from './settle.js'
import type { EntryAddress, KeyAddress, VaultStoreAPI, WrappingRow } from './types.js'

export { vaultRecordPortsFor } from './records-ports.js'
export { VaultRecordRowError } from './records-rows.js'

export type VaultWritePreconditions = {
  copy?: { type: string; owner: string; id: string; expectedOpHash: string }
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

    const rows = await withStoreTransaction(bound.db, async (tx) => {
      let query = tx
        .selectFrom('vault_entry_candidates')
        .selectAll()
        .where('owner', '=', address.ownerDID)
        .where('key_id', '=', address.keyID)

      query = prior
        ? query.where('key_version', '<', version).where('deleted', '=', 1)
        : query.where('key_version', '=', version)

      return query.orderBy('id').orderBy('op_hash').execute()
    })

    // Root-bound resolvers need the connection released before verification.
    return settleAll(
      rows.map(async (row) => {
        const value = await checked(row, bound)

        if (value === null) throw new VaultRecordRowError(row)

        return value.copy
      }),
    )
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

        const expectedCopy = request.preconditions.copy
        if (
          expectedCopy !== undefined &&
          current.get(recordKeyText(expectedCopy))?.copies[0]?.opHash !==
            expectedCopy.expectedOpHash
        )
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

      const rows = await withStoreTransaction(bound.db, async (tx) => {
        return tx
          .selectFrom('vault_key_branches')
          .selectAll()
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .where('key_version', '=', address.keyVersion)
          .orderBy('branch_id')
          .execute()
      })
      // Root-bound resolvers need the connection released before verification.
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

        // A record ID still projected under another key is taken over, as one upsert per row did.
        await settleAll(
          statementChunks(rows, KEY_BRANCH_COLUMNS).map((part) => {
            return upsertKeyBranches(tx, part).execute()
          }),
        )

        return true
      })
    },
    listRevocations: (address) => vaultRecordPortsFor(adapter).listRevocations(address),
    listEntryCandidates: (address) => candidates(address, address.keyVersion, false),
    listPriorEntryTombstones: (address) => candidates(address, address.beforeVersion, true),
  }

  return api
}
