import { chunk, withKeyLocks, withStoreTransaction } from '@hozon/db'
import type { RecordDecision, RecordKey, RecordStoreAdapter } from '@kokuin/records'
import {
  recordClaimDigest,
  recordKeyText,
  recordPayloadMatches,
  recordSignerKey,
  verifySignedRecord,
} from '@kokuin/records'
import { type VAULT_RECORD_TYPES, vaultRecordMeta } from '@kokuin/vault'

import { upsertReplicatedDecision } from './batch.js'
import { getVaultStore } from './definition.js'
import { VaultModeConflict } from './record-context.js'
import { getVaultRecordsStore } from './record-definition.js'
import type { VaultRecordTable } from './record-tables.js'
import { projection } from './records-projection.js'
import type { Bound } from './records-rows.js'
import {
  assertDomain,
  boundAdapters,
  checked,
  decision,
  deleteCopies,
  GET_MANY_CHUNK,
  groupRows,
  supported,
  VaultRecordRowError,
  values,
  whereKey,
} from './records-rows.js'
import { settleAll } from './settle.js'

export function makeAdapter(bound: Bound): RecordStoreAdapter {
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

      const rows = await withStoreTransaction(db, async (tx) => {
        return whereKey(tx, key).orderBy('op_hash').execute()
      })

      // Root-bound resolvers need the connection released before verification.
      return decision(rows, bound)
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
        const dropped = previousRows
          .filter((row, index) => {
            const prior = priors[index] ?? null

            return (
              prior === null ||
              (recordSignerKey(prior.op.issuer, prior.copy.opJWT) === incomingSigner &&
                row.op_hash !== keepHash)
            )
          })
          .map((row) => row.op_hash)

        if (dropped.length > 0) await deleteCopies(db, record, dropped)
      }

      if (keepHash === record.opHash)
        await db
          .insertInto('vault_records')
          .values(values(record, op, bound))
          .onConflict((oc) => oc.columns(['type', 'owner', 'id', 'op_hash']).doNothing())
          .execute()

      // Claims the key for replicated mode and records the decision in one statement. A key
      // held in local mode is left alone and counts no row.
      const claimed = await upsertReplicatedDecision(db, {
        type: record.type,
        owner: record.owner,
        id: record.id,
        content_digest: contentDigest,
        decision_hlc: decisionHLC,
      }).executeTakeFirstOrThrow()

      if (claimed.numInsertedOrUpdatedRows === 0n) throw new VaultModeConflict()
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

      const dropped = verified
        .filter(({ op }) => op?.issuer === signerDID)
        .map(({ copy }) => copy.opHash)

      if (dropped.length > 0) await deleteCopies(db, key, dropped)
    },
  }

  boundAdapters.set(adapter, bound)

  return adapter
}
