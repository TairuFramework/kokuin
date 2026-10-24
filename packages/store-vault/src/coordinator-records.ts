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
import type { EntryRow, VaultStoreAPI, WrappingRow } from './types.js'

type Branch = { branchID: string; branchRecordID: string }

export type EntryInfo = {
  contentHLC: string
  consumer: unknown
}

export type RecordFunctions = {
  wrapping(row: WrappingRow, branch: Branch, consumer?: unknown): Promise<SignedRecord>
  entry(
    row: EntryRow,
    branch: Branch,
    contentHLC: string,
    consumer?: unknown,
    deleted?: boolean,
  ): Promise<SignedRecord>
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
  async function wrapping(
    row: WrappingRow,
    branch: Branch,
    consumer: unknown = null,
  ): Promise<SignedRecord> {
    return ctx.signed('vault.wrapping', { ownerDID: row.ownerDID, id: row.wrappingID }, row, {
      keyID: row.keyID,
      keyVersion: row.keyVersion,
      branchID: branch.branchID,
      branchRecordID: branch.branchRecordID,
      recipient: row.recipientDID,
      consumer,
    })
  }

  async function entry(
    row: EntryRow,
    branch: Branch,
    contentHLC: string,
    consumer: unknown = null,
    deleted = false,
  ): Promise<SignedRecord> {
    return ctx.signed(
      'vault.entry',
      { ownerDID: row.ownerDID, id: row.entryID },
      deleted ? null : row,
      {
        keyID: row.keyID,
        keyVersion: row.keyVersion,
        branchID: branch.branchID,
        branchRecordID: branch.branchRecordID,
        contentHLC,
        consumer,
        ...(deleted ? {} : { kind: row.kind, label: row.label, attributes: row.attributes }),
      },
      row.hlc,
    )
  }

  function checkEntry(row: EntryRow, op: VerifiedRecordOp): EntryInfo {
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
      recordPayloadDigest(encodeVaultRecordPayload('vault.entry', row)) !== op.claim.payloadDigest
    )
      throw new VaultTampered('Entry projection disagrees with authenticated content')

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

    return checkEntry(row, op)
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

    return rows.map((row, index) => {
      const item = evidence[index]

      if (item === undefined) throw new VaultNotFound()

      return checkEntry(row, item.op)
    })
  }

  async function reendorse(
    request: {
      ownerDID: string
      keyID: string
      records: ReadonlyArray<SignedRecord>
    } & CoordinatorCall,
  ): Promise<void> {
    await ctx.authorize('reendorse', 'administer', request)

    if (ctx.params.mode !== 'replicated')
      throw new TypeError('Re-endorsement requires replicated mode')

    const params = ctx.params

    await ctx.locked([request], async (tx) => {
      const decisionsRead = getRecordDecisions(ctx.recordsFor(tx).adapter, request.records)

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
            const op = await ctx.verified(record)

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

      // Signing stays sequential: signer calls follow the caller's record order.
      for (const [index, record] of request.records.entries()) {
        const op = ops[index]

        if (op === undefined) throw new VaultNotFound()

        // Re-sign the entire original claim. Consumer evidence and content intent stay authenticated.
        output.push({
          ...record,
          ...(await signRecordOp(params.signer, op.claim, params.records.opKind)),
        })
      }

      const branches = settledValue(branchesResult)

      await ctx.write(
        tx,
        output,
        {
          key: {
            ...request,
            expectedVersion: key?.version ?? null,
            expectedBranches: branches.map((b) => b.branchID),
          },
        },
        request,
      )
    })
  }

  return { wrapping, entry, entryInfo, entryInfos, reendorse }
}
