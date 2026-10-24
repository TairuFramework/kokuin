import { getSuite } from '@kokuin/vault'

import type { CoordinatorContext } from './coordinator-context.js'
import { VaultNotFound } from './coordinator-context.js'
import type { OpenFunctions } from './coordinator-open.js'
import type { RecordFunctions } from './coordinator-records.js'
import type {
  CoordinatorCall,
  EntryUpdateParams,
  EntryWriteParams,
  OpenedKey,
} from './coordinator-types.js'
import { VaultWriteConflict } from './record-context.js'
import { settleAll } from './settle.js'
import type { EntryAddress, EntryRow, UpdateEntryResult, VaultStoreAPI } from './types.js'

export type ReKeyEntryParams = EntryAddress &
  CoordinatorCall & { toKeyID: string; inputs?: EntryUpdateParams['inputs'] }

export type EntryFunctions = {
  putEntry(request: EntryWriteParams): Promise<EntryAddress>
  deleteEntry(request: EntryAddress & CoordinatorCall): Promise<void>
  reKeyEntry(request: ReKeyEntryParams): Promise<void>
  updateEntry(request: EntryUpdateParams): Promise<void>
  updateEntryIfPresent(request: EntryUpdateParams): Promise<'updated' | 'absent'>
  updateEntryIfUnchanged(
    request: EntryUpdateParams & { expectedHLC: string },
  ): Promise<UpdateEntryResult>
}

const zeroKey = (opened: OpenedKey): void => {
  opened.contentKey.fill(0)
}

const zeroBytes = (bytes: Uint8Array): void => {
  bytes.fill(0)
}

export function createEntryFunctions(
  ctx: CoordinatorContext,
  open: OpenFunctions,
  records: RecordFunctions,
): EntryFunctions {
  const { params } = ctx

  async function save(
    row: EntryRow,
    store: VaultStoreAPI,
    call: CoordinatorCall,
    expectedHLC: string | null,
    consumer: unknown,
  ): Promise<void> {
    if (params.mode === 'local') {
      await store.putEntry(row)

      return
    }

    const key = await ctx.key(row, store)
    const [branch, branches] = await settleAll([
      ctx.branch(key, key.version, store),
      ctx.branches(key, key.version, store),
    ])
    const record = await records.entry(row, branch, row.hlc, consumer)

    await ctx.write(
      store,
      [record],
      {
        key: {
          ...key,
          expectedVersion: key.version,
          expectedBranches: branches.map((b) => b.branchID),
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

      const [key, opened, hlc] = await settleAll(
        [ctx.key(request, store), open.open(request, store), params.nextHLC()],
        [undefined, zeroKey],
      )

      try {
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
  ): Promise<UpdateEntryResult> {
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

      const [opened, hlc, info] = await settleAll(
        [
          open.open({ ...existing, inputs: request.inputs }, store),
          params.nextHLC(),
          records.entryInfo(existing, store),
        ],
        [zeroKey],
      )

      try {
        const row = {
          ...existing,
          keyVersion: opened.version,
          hlc,
          provenance: opened.branchID,
          ...getSuite(opened.suite).encryptEntry({
            ...existing,
            keyVersion: opened.version,
            runtime: params.runtime,
            contentKey: opened.contentKey,
            plaintext: request.plaintext,
          }),
        }

        await save(row, store, request, existing.hlc, info.consumer)

        return 'updated'
      } finally {
        opened.contentKey.fill(0)
      }
    })
  }

  async function deleteEntry(request: EntryAddress & CoordinatorCall): Promise<void> {
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

      const keyBranch = async () => {
        const key = await ctx.key(existing, store)

        return { key, branch: await ctx.branch(existing, key.version, store) }
      }
      const [{ key, branch }, info, hlc] = await settleAll([
        keyBranch(),
        records.entryInfo(existing, store),
        params.nextHLC(),
      ])
      const row = { ...existing, hlc, keyVersion: key.version }
      const record = await records.entry(row, branch, row.hlc, info.consumer, true)

      await ctx.write(
        store,
        [record],
        {
          key: { ...key, expectedVersion: key.version },
          entry: { ...request, expectedHLC: existing.hlc },
        },
        request,
      )
    })
  }

  async function reKeyEntry(request: ReKeyEntryParams): Promise<void> {
    await ctx.authorize('reKeyEntry', 'administer', request)

    const observed = await params.store.getEntry(request)

    if (observed === undefined) throw new VaultNotFound()

    const target = { ownerDID: request.ownerDID, keyID: request.toKeyID }

    await settleAll([
      ctx.authorize('reKeyEntry', 'administer', { ...request, keyID: observed.keyID }),
      ctx.authorize('reKeyEntry', 'administer', { ...request, keyID: target.keyID }),
    ])
    await ctx.locked([observed, target], async (store) => {
      const existing = await store.getEntry(request)

      if (
        existing === undefined ||
        existing.keyID !== observed.keyID ||
        existing.hlc !== observed.hlc
      )
        throw new VaultWriteConflict()

      const decrypting = open.decrypt(existing, { ...existing, inputs: request.inputs }, store)
      // A rejected source PIN must not also spend an attempt on the target key's throttle.
      const opening =
        request.inputs?.pin === undefined
          ? open.open({ ...target, inputs: request.inputs }, store)
          : decrypting.then(() => open.open({ ...target, inputs: request.inputs }, store))
      const [plaintext, opened, info, hlc] = await settleAll(
        [decrypting, opening, records.entryInfo(existing, store), params.nextHLC()],
        [zeroBytes, zeroKey],
      )

      try {
        const row: EntryRow = {
          ...existing,
          ...target,
          keyVersion: opened.version,
          hlc,
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
        plaintext.fill(0)
      }
    })
  }

  return {
    putEntry,
    deleteEntry,
    reKeyEntry,
    async updateEntry(request: EntryUpdateParams): Promise<void> {
      if ((await update(request, 'updateEntry')) !== 'updated') throw new VaultNotFound()
    },
    async updateEntryIfPresent(request: EntryUpdateParams): Promise<'updated' | 'absent'> {
      const result = await update(request, 'updateEntryIfPresent')

      if (result === 'superseded') throw new VaultWriteConflict()

      return result
    },
    updateEntryIfUnchanged: (
      request: EntryUpdateParams & { expectedHLC: string },
    ): Promise<UpdateEntryResult> => {
      return update(request, 'updateEntryIfUnchanged')
    },
  }
}
