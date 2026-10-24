import type { SignedRecord } from '@kokuin/records'
import { compareRecordDecisionHLC } from '@kokuin/records'
import {
  decodeVaultRecord,
  factorsFromDescriptors,
  getSuite,
  NoAvailableFactor,
  vaultRevocationRecordID,
} from '@kokuin/vault'

import type { CoordinatorContext } from './coordinator-context.js'
import { VaultKeyLocked, VaultNotFound, VaultRepairPending } from './coordinator-context.js'
import type { OpenFunctions } from './coordinator-open.js'
import type { RecordFunctions } from './coordinator-records.js'
import type { ForkRepairResult, RotateKeyParams } from './coordinator-types.js'
import type { EntryRow, KeyRow, VaultStoreAPI, WrappingRow } from './types.js'

type Selection = {
  entryID: string
  row?: EntryRow
  contentHLC: string
  consumer: unknown
  opHash: string
  keyVersion: number
  branchID: string
}
export function createRotateFunctions(
  ctx: CoordinatorContext,
  open: OpenFunctions,
  records: RecordFunctions,
) {
  const { params } = ctx
  function excluded(row: WrappingRow, recipients: ReadonlyArray<string>) {
    const denied = new Set(recipients.map((did) => vaultRevocationRecordID(row.keyID, did)))
    return [
      row.recipientDID,
      ...row.descriptors.filter((d) => d.kind === 'did').map((d) => d.params.recipient),
    ].some((did) => typeof did === 'string' && denied.has(vaultRevocationRecordID(row.keyID, did)))
  }
  async function currentEntries(key: KeyRow, store: VaultStoreAPI): Promise<Array<Selection>> {
    const result: Array<Selection> = []
    for (const row of await store.listEntries(key)) {
      const info = await records.entryInfo(row, store)
      result.push({
        entryID: row.entryID,
        row,
        ...info,
        opHash: '',
        keyVersion: row.keyVersion,
        branchID: row.provenance,
      })
    }
    return result
  }
  async function candidates(
    key: KeyRow,
    store: VaultStoreAPI,
  ): Promise<Map<string, Array<Selection>>> {
    const api = ctx.recordsFor(store)
    const values = [
      ...(await api.listEntryCandidates({ ...key, keyVersion: key.version })),
      ...(await api.listPriorEntryTombstones({ ...key, beforeVersion: key.version })),
    ]
    const grouped = new Map<string, Array<Selection>>()
    for (const record of values) {
      const op = await ctx.verified(record)
      const meta = op.claim.meta
      if (
        op.claim.owner !== key.ownerDID ||
        meta.keyID !== key.keyID ||
        typeof meta.contentHLC !== 'string' ||
        typeof meta.keyVersion !== 'number'
      )
        throw new VaultRepairPending()
      let row: EntryRow | undefined
      if (!op.claim.deleted) {
        const decoded = decodeVaultRecord(record, meta)
        if (
          decoded.type !== 'vault.entry' ||
          decoded.meta.kind === undefined ||
          decoded.meta.label === undefined ||
          decoded.meta.attributes === undefined ||
          decoded.meta.branchID === undefined
        )
          throw new VaultRepairPending()
        row = {
          ownerDID: key.ownerDID,
          keyID: key.keyID,
          entryID: record.id,
          keyVersion: meta.keyVersion,
          hlc: record.hlc,
          provenance: decoded.meta.branchID,
          kind: decoded.meta.kind,
          label: decoded.meta.label,
          attributes: decoded.meta.attributes,
          ...decoded.payload,
        }
      }
      const value = {
        entryID: record.id,
        row,
        contentHLC: meta.contentHLC,
        consumer: meta.consumer,
        opHash: record.opHash,
        keyVersion: meta.keyVersion,
        branchID: typeof meta.branchID === 'string' ? meta.branchID : '',
      }
      const list = grouped.get(record.id) ?? []
      list.push(value)
      grouped.set(record.id, list)
    }
    return grouped
  }
  const compare = (a: Selection, b: Selection) =>
    compareRecordDecisionHLC(a.contentHLC, b.contentHLC) ||
    a.keyVersion - b.keyVersion ||
    (a.opHash < b.opHash ? -1 : a.opHash > b.opHash ? 1 : 0)
  async function rotateLocked(
    request: RotateKeyParams,
    store: VaultStoreAPI,
    repair: boolean,
  ): Promise<number | null> {
    if (!Array.isArray(request.excludedRecipients) || !Array.isArray(request.reissue))
      throw new TypeError('Explicit exclusions and entry reissue instructions are required')
    const key = await ctx.key(request, store)
    const branches = await ctx.branches(key, key.version, store)
    if (repair && branches.length < 2) return null
    const winner = await ctx.branch(key, key.version, store)
    const expectedBranches = branches.map((b) => b.branchID)
    const existingWrappings = await store.listWrappings(key)
    const currentWrappings = existingWrappings.filter((w) => w.keyVersion === key.version)
    for (const wrapping of currentWrappings) await ctx.wrappingEvidence(wrapping, store)
    let retained = currentWrappings.filter((w) => !excluded(w, request.excludedRecipients))
    let selections = await currentEntries(key, store)
    const keys = new Map<string, { contentKey: Uint8Array; suite: number }>()
    const plaintexts: Array<Uint8Array> = []
    let generated: Uint8Array | undefined
    try {
      const decrypt = async (selection: Selection): Promise<Uint8Array | null> => {
        if (selection.row === undefined) return null
        const row = selection.row
        const identity = JSON.stringify([row.keyVersion, row.provenance])
        let source = keys.get(identity)
        if (source === undefined) {
          const opened = await open.open(
            { ...request, atVersion: row.keyVersion },
            store,
            params.mode === 'replicated' ? row.provenance : undefined,
          )
          source = { contentKey: opened.contentKey, suite: opened.suite }
          keys.set(identity, source)
        }
        const plaintext = getSuite(source.suite).decryptEntry({
          ...row,
          contentKey: source.contentKey,
        })
        plaintexts.push(plaintext)
        return plaintext
      }
      if (repair) {
        const grouped = await candidates(key, store)
        const selected: Array<Selection> = []
        let addsEntry = false
        for (const list of grouped.values()) {
          list.sort(compare)
          const chosen = list.at(-1)
          if (chosen === undefined) continue
          selected.push(chosen)
          if (chosen.branchID === winner.branchID) continue
          const winning = list
            .filter((s) => s.branchID === winner.branchID)
            .sort(compare)
            .at(-1)
          if (winning === undefined || chosen.contentHLC !== winning.contentHLC) {
            addsEntry = true
            continue
          }
          const a = await decrypt(chosen)
          const b = await decrypt(winning)
          if (
            (a === null) !== (b === null) ||
            (a !== null && b !== null && (a.length !== b.length || !a.every((v, i) => v === b[i])))
          )
            addsEntry = true
        }
        const signature = (w: WrappingRow) =>
          JSON.stringify({
            recipient: w.recipientDID,
            factors: factorsFromDescriptors(w.descriptors, request.inputs),
          })
        const winnerRecipients = new Set(
          retained.filter((w) => w.provenance === winner.branchID).map(signature),
        )
        const addsRecipient = retained.some((w) => !winnerRecipients.has(signature(w)))
        let unreadableProjection = false
        for (const selection of selections) {
          if (selection.row === undefined) continue
          const branch = await ctx.branch(key, selection.keyVersion, store)
          if (selection.branchID !== branch.branchID) {
            unreadableProjection = true
            break
          }
        }
        if (
          !addsEntry &&
          !addsRecipient &&
          !unreadableProjection &&
          request.reissue.length === 0 &&
          request.excludedRecipients.length === 0
        )
          return null
        const unique = new Map<string, WrappingRow>()
        for (const wrapping of [
          ...retained.filter((w) => w.provenance === winner.branchID),
          ...retained,
        ]) {
          const id = signature(wrapping)
          if (!unique.has(id)) unique.set(id, wrapping)
        }
        retained = [...unique.values()]
        selections = selected
      }
      const instructions = new Map(
        request.reissue.map((instruction) => [instruction.entryID, instruction]),
      )
      if (
        instructions.size !== request.reissue.length ||
        [...instructions.keys()].some((id) => !selections.some((s) => s.entryID === id))
      )
        throw new TypeError('Reissue instructions must name distinct existing entries')
      const suite = getSuite(request.suite ?? key.suite)
      const next = { ...key, version: key.version + 1, suite: suite.id }
      generated = suite.generateContentKey(params.runtime)
      const output: Array<SignedRecord> = []
      const chain =
        params.mode === 'replicated'
          ? await ctx.keyRecords(next, store)
          : { records: [], branchID: '', branchRecordID: '' }
      output.push(...chain.records)
      const wrappings: Array<WrappingRow> = []
      for (const previous of retained) {
        const wrappingID = params.runtime.getRandomID()
        const wrapped = await suite.wrap({
          runtime: params.runtime,
          contentKey: generated,
          factors: factorsFromDescriptors(previous.descriptors, request.inputs),
          wrappingID,
          keyID: key.keyID,
          keyVersion: next.version,
          methods: params.methods,
        })
        const row = {
          ...next,
          wrappingID,
          keyVersion: next.version,
          recipientDID: previous.recipientDID,
          provenance: chain.branchID,
          ...wrapped,
        }
        wrappings.push(row)
        if (params.mode === 'replicated') {
          const { op } = await ctx.stored(
            { type: 'vault.wrapping', owner: previous.ownerDID, id: previous.wrappingID },
            store,
          )
          output.push(await records.wrapping(row, chain, op.claim.meta.consumer))
        }
      }
      const entries: Array<EntryRow> = []
      const deletions: Array<string> = []
      for (const selected of selections) {
        const instruction = instructions.get(selected.entryID)
        if (instruction?.action === 'skip') continue
        const deleting =
          instruction?.action === 'delete' ||
          (selected.row === undefined && instruction?.action !== 'replace')
        const contentHLC = instruction?.contentHLC ?? selected.contentHLC
        const consumer =
          instruction !== undefined && Object.hasOwn(instruction, 'consumer')
            ? instruction.consumer
            : selected.consumer
        const hlc = await params.nextHLC()
        if (deleting) {
          deletions.push(selected.entryID)
          if (params.mode === 'replicated')
            output.push(
              await ctx.signed(
                'vault.entry',
                { ownerDID: key.ownerDID, id: selected.entryID },
                null,
                {
                  keyID: key.keyID,
                  keyVersion: next.version,
                  branchID: chain.branchID,
                  branchRecordID: chain.branchRecordID,
                  contentHLC,
                  consumer,
                },
                hlc,
              ),
            )
          continue
        }
        const plaintext =
          instruction?.action === 'replace' ? instruction.plaintext : await decrypt(selected)
        if (plaintext === null || selected.row === undefined) throw new VaultRepairPending()
        const encrypted = suite.encryptEntry({
          runtime: params.runtime,
          contentKey: generated,
          plaintext,
          keyID: key.keyID,
          keyVersion: next.version,
          entryID: selected.entryID,
        })
        const row = {
          ...selected.row,
          keyVersion: next.version,
          ...encrypted,
          hlc,
          provenance: chain.branchID,
        }
        entries.push(row)
        if (params.mode === 'replicated')
          output.push(await records.entry(row, chain, contentHLC, consumer))
      }
      if (params.mode === 'replicated') {
        for (const did of new Set(request.excludedRecipients)) {
          const id = vaultRevocationRecordID(key.keyID, did)
          const revokedDID = id.slice(id.indexOf('/') + 1)
          output.push(
            await ctx.signed(
              'vault.revocation',
              { ownerDID: key.ownerDID, id },
              {},
              { keyID: key.keyID, revokedDID, consumer: null },
            ),
          )
        }
        await ctx.write(
          store,
          output,
          { key: { ...key, expectedVersion: key.version, expectedBranches } },
          request,
        )
      } else {
        await store.putKey(next)
        for (const wrapping of wrappings) await store.putWrapping(wrapping)
        for (const entry of entries) await store.putEntry(entry)
        for (const entryID of deletions)
          await store.deleteEntry({ ownerDID: key.ownerDID, entryID })
        for (const row of existingWrappings.filter((w) => excluded(w, request.excludedRecipients)))
          await store.deleteWrapping(row)
      }
      return next.version
    } finally {
      for (const source of keys.values()) source.contentKey.fill(0)
      for (const plaintext of plaintexts) plaintext.fill(0)
      generated?.fill(0)
    }
  }
  async function rotate(request: RotateKeyParams) {
    await ctx.authorize('rotate', 'administer', request)
    const version = await ctx.locked([request], (tx) => rotateLocked(request, tx, false))
    if (version === null) throw new VaultNotFound()
    ctx.evict(request)
    return version
  }
  async function repairFork(request: RotateKeyParams): Promise<ForkRepairResult> {
    await ctx.authorize('repairFork', 'administer', request)
    if (params.mode === 'local') return { status: 'not-needed' }
    try {
      const version = await ctx.locked([request], (tx) => rotateLocked(request, tx, true))
      if (version === null) return { status: 'not-needed' }
      ctx.evict(request)
      return { status: 'rotated', version }
    } catch (error) {
      if (
        error instanceof VaultRepairPending ||
        error instanceof VaultKeyLocked ||
        error instanceof NoAvailableFactor
      )
        return { status: 'pending' }
      throw error
    }
  }
  return { rotate, repairFork }
}
