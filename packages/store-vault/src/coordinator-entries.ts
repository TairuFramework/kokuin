import { getSuite } from '@kokuin/vault'

import type { CoordinatorContext } from './coordinator-context.js'
import { VaultNotFound } from './coordinator-context.js'
import type { OpenFunctions } from './coordinator-open.js'
import type { RecordFunctions } from './coordinator-records.js'
import type { CoordinatorCall, EntryUpdateParams, EntryWriteParams } from './coordinator-types.js'
import { VaultWriteConflict } from './record-context.js'
import type { EntryAddress, EntryRow, VaultStoreAPI } from './types.js'

export function createEntryFunctions(
  ctx: CoordinatorContext,
  open: OpenFunctions,
  records: RecordFunctions,
) {
  const { params } = ctx
  async function save(
    row: EntryRow,
    store: VaultStoreAPI,
    call: CoordinatorCall,
    expectedHLC: string | null,
    consumer: unknown,
  ) {
    if (params.mode === 'local') {
      await store.putEntry(row)
      return
    }
    const key = await ctx.key(row, store)
    const branch = await ctx.branch(key, key.version, store)
    await ctx.write(
      store,
      [await records.entry(row, branch, row.hlc, consumer)],
      {
        key: {
          ...key,
          expectedVersion: key.version,
          expectedBranches: (await ctx.branches(key, key.version, store)).map((b) => b.branchID),
        },
        entry: { ...row, expectedHLC },
      },
      call,
    )
  }
  async function putEntry(request: EntryWriteParams): Promise<EntryAddress> {
    await ctx.authorize('putEntry', 'administer', request)
    return ctx.locked([request], async (store) => {
      const current = await store.getEntry(request)
      if (current !== undefined) throw new VaultWriteConflict()
      const key = await ctx.key(request, store)
      const opened = await open.open(request, store)
      try {
        const hlc = await params.nextHLC()
        const encrypted = getSuite(opened.suite).encryptEntry({
          ...request,
          runtime: params.runtime,
          contentKey: opened.contentKey,
          keyVersion: key.version,
        })
        const row: EntryRow = {
          ...request,
          keyVersion: key.version,
          ...encrypted,
          hlc,
          provenance: opened.branchID,
        }
        await save(row, store, request, null, request.consumer ?? null)
        return { ownerDID: request.ownerDID, entryID: request.entryID }
      } finally {
        opened.contentKey.fill(0)
      }
    })
  }
  async function update(
    request: EntryUpdateParams & { expectedHLC?: string },
    operation: string,
  ): Promise<'updated' | 'absent' | 'superseded'> {
    await ctx.authorize(operation, 'administer', request)
    const observed = await params.store.getEntry(request)
    if (observed === undefined) return 'absent'
    return ctx.locked([observed], async (store) => {
      const existing = await store.getEntry(request)
      if (existing === undefined) return 'absent'
      if (existing.keyID !== observed.keyID) throw new VaultWriteConflict()
      if (request.expectedHLC !== undefined && existing.hlc !== request.expectedHLC)
        return 'superseded'
      await ctx.authorize(operation, 'administer', { ...request, keyID: existing.keyID }, store)
      const opened = await open.open({ ...existing, inputs: request.inputs }, store)
      try {
        const row = {
          ...existing,
          keyVersion: opened.version,
          hlc: await params.nextHLC(),
          provenance: opened.branchID,
          ...getSuite(opened.suite).encryptEntry({
            ...existing,
            keyVersion: opened.version,
            runtime: params.runtime,
            contentKey: opened.contentKey,
            plaintext: request.plaintext,
          }),
        }
        const info = await records.entryInfo(existing, store)
        await save(row, store, request, existing.hlc, info.consumer)
        return 'updated'
      } finally {
        opened.contentKey.fill(0)
      }
    })
  }
  async function deleteEntry(request: EntryAddress & CoordinatorCall) {
    await ctx.authorize('deleteEntry', 'administer', request)
    const observed = await params.store.getEntry(request)
    if (observed === undefined) return
    await ctx.locked([observed], async (store) => {
      const existing = await store.getEntry(request)
      if (existing === undefined) return
      if (existing.keyID !== observed.keyID) throw new VaultWriteConflict()
      await ctx.authorize('deleteEntry', 'administer', { ...request, keyID: existing.keyID }, store)
      if (params.mode === 'local') {
        await store.deleteEntry(request)
        return
      }
      const key = await ctx.key(existing, store)
      const branch = await ctx.branch(existing, key.version, store)
      const info = await records.entryInfo(existing, store)
      const row = { ...existing, hlc: await params.nextHLC(), keyVersion: key.version }
      await ctx.write(
        store,
        [await records.entry(row, branch, row.hlc, info.consumer, true)],
        {
          key: { ...key, expectedVersion: key.version },
          entry: { ...request, expectedHLC: existing.hlc },
        },
        request,
      )
    })
  }
  async function reKeyEntry(
    request: EntryAddress &
      CoordinatorCall & { toKeyID: string; inputs?: EntryUpdateParams['inputs'] },
  ) {
    await ctx.authorize('reKeyEntry', 'administer', request)
    const observed = await params.store.getEntry(request)
    if (observed === undefined) throw new VaultNotFound()
    const target = { ownerDID: request.ownerDID, keyID: request.toKeyID }
    await ctx.authorize('reKeyEntry', 'administer', { ...request, keyID: observed.keyID })
    await ctx.authorize('reKeyEntry', 'administer', { ...request, keyID: target.keyID })
    await ctx.locked([observed, target], async (store) => {
      const existing = await store.getEntry(request)
      if (
        existing === undefined ||
        existing.keyID !== observed.keyID ||
        existing.hlc !== observed.hlc
      )
        throw new VaultWriteConflict()
      const plaintext = await open.decrypt(existing, { ...existing, inputs: request.inputs }, store)
      try {
        const opened = await open.open({ ...target, inputs: request.inputs }, store)
        try {
          const info = await records.entryInfo(existing, store)
          const row: EntryRow = {
            ...existing,
            ...target,
            keyVersion: opened.version,
            hlc: await params.nextHLC(),
            provenance: opened.branchID,
            ...getSuite(opened.suite).encryptEntry({
              ...target,
              keyVersion: opened.version,
              entryID: existing.entryID,
              contentKey: opened.contentKey,
              runtime: params.runtime,
              plaintext,
            }),
          }
          if (params.mode === 'local') await store.moveEntry(row)
          else await save(row, store, request, existing.hlc, info.consumer)
        } finally {
          opened.contentKey.fill(0)
        }
      } finally {
        plaintext.fill(0)
      }
    })
  }
  return {
    putEntry,
    deleteEntry,
    reKeyEntry,
    async updateEntry(request: EntryUpdateParams) {
      if ((await update(request, 'updateEntry')) !== 'updated') throw new VaultNotFound()
    },
    async updateEntryIfPresent(request: EntryUpdateParams): Promise<'updated' | 'absent'> {
      const result = await update(request, 'updateEntryIfPresent')
      if (result === 'superseded') throw new VaultWriteConflict()
      return result
    },
    updateEntryIfUnchanged: (request: EntryUpdateParams & { expectedHLC: string }) =>
      update(request, 'updateEntryIfUnchanged'),
  }
}
