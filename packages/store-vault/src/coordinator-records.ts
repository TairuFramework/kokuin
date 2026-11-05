import type { SignedRecord, VerifiedRecordOp } from '@kokuin/records'
import {
  getRecordDecisions,
  recordKeyText,
  recordPayloadDigest,
  signRecordOp,
} from '@kokuin/records'
import { encodeVaultRecordPayload, VaultTampered } from '@kokuin/vault'

import type { CoordinatorContext } from './coordinator-context.js'
import { VaultNotFound } from './coordinator-context.js'
import type { CoordinatorCall } from './coordinator-types.js'
import { settleAll, settledValue } from './settle.js'
import { snapshotCall } from './snapshot.js'
import type { EntryRow, VaultStoreAPI, WrappingRow } from './types.js'

type WrappingParams = { row: WrappingRow; branch: Branch; consumer?: unknown; hlc?: string }
type EntryParams = {
  row: EntryRow
  branch: Branch
  contentHLC: string
  consumer?: unknown
  deleted?: boolean
}

type Branch = { branchID: string; branchRecordID: string }

export type EntryInfo = {
  contentHLC: string
  consumer: unknown
}

export type RecordFunctions = {
  /** Signs at `hlc` when given, or at a newly allocated one. */
  wrapping(params: WrappingParams): Promise<SignedRecord>
  entry(params: EntryParams): Promise<SignedRecord>
  entryInfo(row: EntryRow, store: VaultStoreAPI): Promise<EntryInfo>
  /** Batched {@link entryInfo}: one record read, results and the first failure in row order. */
  entryInfos(rows: ReadonlyArray<EntryRow>, store: VaultStoreAPI): Promise<Array<EntryInfo>>
  reendorse(
    request: {
      ownerDID: string
      keyID: string
      records: ReadonlyArray<SignedRecord>
    } & CoordinatorCall,
  ): Promise<void>
}

export function createRecordFunctions(ctx: CoordinatorContext): RecordFunctions {
  async function wrapping({
    row,
    branch,
    consumer = null,
    hlc,
  }: WrappingParams): Promise<SignedRecord> {
    return ctx.signed({
      type: 'vault.wrapping',
      address: { ownerDID: row.ownerDID, id: row.wrappingID },
      payload: row,
      meta: {
        keyID: row.keyID,
        keyVersion: row.keyVersion,
        branchID: branch.branchID,
        branchRecordID: branch.branchRecordID,
        recipient: row.recipientDID,
        consumer,
      },
      hlc,
    })
  }

  async function entry({
    row,
    branch,
    contentHLC,
    consumer = null,
    deleted = false,
  }: EntryParams): Promise<SignedRecord> {
    return ctx.signed({
      type: 'vault.entry',
      address: { ownerDID: row.ownerDID, id: row.entryID },
      payload: deleted ? null : row,
      meta: {
        keyID: row.keyID,
        keyVersion: row.keyVersion,
        branchID: branch.branchID,
        branchRecordID: branch.branchRecordID,
        contentHLC,
        consumer,
        ...(deleted ? {} : { kind: row.kind, label: row.label, attributes: row.attributes }),
      },
      hlc: row.hlc,
    })
  }

  async function checkEntry(row: EntryRow, op: VerifiedRecordOp): Promise<EntryInfo> {
    const meta = op.claim.meta
    const attributes = meta.attributes

    if (
      op.claim.deleted ||
      op.claim.hlc !== row.hlc ||
      meta.keyID !== row.keyID ||
      meta.keyVersion !== row.keyVersion ||
      meta.branchID !== row.provenance ||
      meta.kind !== row.kind ||
      meta.label !== row.label ||
      attributes === null ||
      typeof attributes !== 'object' ||
      Array.isArray(attributes) ||
      Object.keys(attributes).length !== Object.keys(row.attributes).length ||
      Object.entries(attributes).some(([name, value]) => row.attributes[name] !== value) ||
      (await recordPayloadDigest({
        ...ctx.params,
        payload: encodeVaultRecordPayload({ type: 'vault.entry', payload: row }),
      })) !== op.claim.payloadDigest
    )
      throw new VaultTampered({ message: 'Entry projection disagrees with authenticated content' })

    const contentHLC = op.claim.meta.contentHLC

    if (typeof contentHLC !== 'string') throw new VaultNotFound()

    return { contentHLC, consumer: op.claim.meta.consumer }
  }

  async function entryInfo(row: EntryRow, store: VaultStoreAPI): Promise<EntryInfo> {
    if (ctx.params.mode === 'local') return { contentHLC: row.hlc, consumer: null }

    const { op } = await ctx.stored(
      { type: 'vault.entry', owner: row.ownerDID, id: row.entryID },
      store,
    )

    return await checkEntry(row, op)
  }

  async function entryInfos(
    rows: ReadonlyArray<EntryRow>,
    store: VaultStoreAPI,
  ): Promise<Array<EntryInfo>> {
    if (ctx.params.mode === 'local')
      return rows.map((row) => ({ contentHLC: row.hlc, consumer: null }))

    const evidence = await ctx.storedMany(
      rows.map((row) => ({ type: 'vault.entry', owner: row.ownerDID, id: row.entryID })),
      store,
    )

    return await Promise.all(
      rows.map(async (row, index) => {
        const item = evidence[index]

        if (item === undefined) throw new VaultNotFound()

        return await checkEntry(row, item.op)
      }),
    )
  }

  async function reendorse(
    input: {
      ownerDID: string
      keyID: string
      records: ReadonlyArray<SignedRecord>
    } & CoordinatorCall,
  ): Promise<void> {
    const request = snapshotCall(input)
    await ctx.authorize({ operation: 'reendorse', verb: 'administer', address: request })

    if (ctx.params.mode !== 'replicated')
      throw new TypeError('Re-endorsement requires replicated mode')

    const params = ctx.params

    await ctx.locked([request], async (tx) => {
      const decisionsRead = getRecordDecisions({
        store: ctx.recordsFor(tx).adapter,
        keys: request.records,
      })

      // A task that fails before reading the decisions must not leave this rejection unhandled.
      decisionsRead.catch(() => {})

      const keyRead = tx.getKey(request)
      const branchesRead = keyRead.then((key) => ctx.branches(request, key?.version ?? 0, tx))
      // All reads run together. Results are checked in the old order: key, then each record,
      // then, after signing, the branches.
      const [keyResult, opsResult, branchesResult] = await Promise.allSettled([
        keyRead,
        settleAll(
          request.records.map(async (record) => {
            const op = await ctx.verified(record, tx)

            if (op.claim.owner !== request.ownerDID || op.claim.meta.keyID !== request.keyID)
              throw new TypeError('Re-endorsement is confined to the explicitly named key')

            const decision = (await decisionsRead).get(recordKeyText(record))

            if (!decision?.copies.some((copy) => copy.opHash === record.opHash))
              throw new VaultNotFound()

            return op
          }),
        ),
        branchesRead,
      ])
      const key = settledValue(keyResult)
      const ops = settledValue(opsResult)
      const output: Array<SignedRecord> = []

      // Signing stays sequential: signer calls follow the caller's record order, and a failure
      // stops the rest.
      for (const [index, record] of request.records.entries()) {
        const op = ops[index]

        if (op === undefined) throw new VaultNotFound()

        // Re-sign the entire original claim. Consumer evidence and content intent stay authenticated.
        output.push({
          ...record,
          ...(await signRecordOp({
            identity: params.signer,
            claim: op.claim,
            opKind: params.records.opKind,
            crypto: params?.crypto,
          })),
        })
      }

      const branches = settledValue(branchesResult)

      await ctx.write({
        store: tx,
        output,
        preconditions: {
          key: {
            ...request,
            expectedVersion: key?.version ?? null,
            expectedBranches: branches.map((b) => b.branchID),
          },
        },
        call: request,
      })
    })
  }

  return { wrapping, entry, entryInfo, entryInfos, reendorse }
}
