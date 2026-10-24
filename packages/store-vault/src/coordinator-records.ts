import { recordPayloadDigest, signRecordOp } from '@kokuin/records'
import { encodeVaultRecordPayload, VaultTampered } from '@kokuin/vault'

import type { CoordinatorContext } from './coordinator-context.js'
import { VaultNotFound } from './coordinator-context.js'
import type { CoordinatorCall } from './coordinator-types.js'
import type { EntryRow, VaultStoreAPI, WrappingRow } from './types.js'

type Branch = { branchID: string; branchRecordID: string }
export function createRecordFunctions(ctx: CoordinatorContext) {
  async function wrapping(row: WrappingRow, branch: Branch, consumer: unknown = null) {
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
  ) {
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
  async function entryInfo(row: EntryRow, store: VaultStoreAPI) {
    if (ctx.params.mode === 'local') return { contentHLC: row.hlc, consumer: null }
    const { op } = await ctx.stored(
      { type: 'vault.entry', owner: row.ownerDID, id: row.entryID },
      store,
    )
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
  async function reendorse(
    request: {
      ownerDID: string
      keyID: string
      records: ReadonlyArray<Parameters<CoordinatorContext['verified']>[0]>
    } & CoordinatorCall,
  ) {
    await ctx.authorize('reendorse', 'administer', request)
    if (ctx.params.mode !== 'replicated')
      throw new TypeError('Re-endorsement requires replicated mode')
    const params = ctx.params
    await ctx.locked([request], async (tx) => {
      const key = await tx.getKey(request)
      const output = []
      for (const record of request.records) {
        const op = await ctx.verified(record)
        if (op.claim.owner !== request.ownerDID || op.claim.meta.keyID !== request.keyID)
          throw new TypeError('Re-endorsement is confined to the explicitly named key')
        const decision = await ctx.recordsFor(tx).adapter.get(record)
        if (!decision?.copies.some((copy) => copy.opHash === record.opHash))
          throw new VaultNotFound()
        // Re-sign the entire original claim. Consumer evidence and content intent stay authenticated.
        output.push({
          ...record,
          ...(await signRecordOp(params.signer, op.claim, params.records.opKind)),
        })
      }
      await ctx.write(
        tx,
        output,
        {
          key: {
            ...request,
            expectedVersion: key?.version ?? null,
            expectedBranches: (await ctx.branches(request, key?.version ?? 0, tx)).map(
              (b) => b.branchID,
            ),
          },
        },
        request,
      )
    })
  }
  return { wrapping, entry, entryInfo, reendorse }
}
export type RecordFunctions = ReturnType<typeof createRecordFunctions>
