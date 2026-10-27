import type { SignedRecord } from '@kokuin/records'
import { compareRecordDecisionHLC } from '@kokuin/records'
import {
  decodeVaultRecord,
  factorsFromDescriptors,
  getSuite,
  isSecretFactorKind,
  NoAvailableFactor,
  vaultRevocationRecordID,
} from '@kokuin/vault'

import type { CoordinatorContext, KeyBranch, WrappingEvidence } from './coordinator-context.js'
import { VaultKeyLocked, VaultNotFound, VaultRepairPending } from './coordinator-context.js'
import type { OpenFunctions } from './coordinator-open.js'
import type { RecordFunctions } from './coordinator-records.js'
import type { ForkRepairResult, RotateKeyParams } from './coordinator-types.js'
import { VaultWriteConflict } from './record-context.js'
import { settleAll } from './settle.js'
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

type SourceKey = { contentKey: Uint8Array; suite: number }

export type RotateFunctions = {
  rotate(request: RotateKeyParams): Promise<number>
  repairFork(request: RotateKeyParams): Promise<ForkRepairResult>
}

export function createRotateFunctions(
  ctx: CoordinatorContext,
  open: OpenFunctions,
  records: RecordFunctions,
): RotateFunctions {
  const { params } = ctx

  function excluded(row: WrappingRow, recipients: ReadonlyArray<string>): boolean {
    const denied = new Set(recipients.map((did) => vaultRevocationRecordID(row.keyID, did)))

    return [
      row.recipientDID,
      ...row.descriptors.filter((d) => d.kind === 'did').map((d) => d.params.recipient),
    ].some((did) => typeof did === 'string' && denied.has(vaultRevocationRecordID(row.keyID, did)))
  }

  async function currentEntries(key: KeyRow, store: VaultStoreAPI): Promise<Array<Selection>> {
    const rows = await store.listEntries(key)
    const infos = await records.entryInfos(rows, store)

    return rows.map((row, index) => {
      const info = infos[index]

      if (info === undefined) throw new VaultNotFound()

      return {
        entryID: row.entryID,
        row,
        ...info,
        opHash: '',
        keyVersion: row.keyVersion,
        branchID: row.provenance,
      }
    })
  }

  async function candidate(key: KeyRow, record: SignedRecord): Promise<Selection> {
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

    return {
      entryID: record.id,
      row,
      contentHLC: meta.contentHLC,
      consumer: meta.consumer,
      opHash: record.opHash,
      keyVersion: meta.keyVersion,
      branchID: typeof meta.branchID === 'string' ? meta.branchID : '',
    }
  }

  async function candidates(
    key: KeyRow,
    store: VaultStoreAPI,
  ): Promise<Map<string, Array<Selection>>> {
    const api = ctx.recordsFor(store)
    const [current, prior] = await settleAll([
      api.listEntryCandidates({ ...key, keyVersion: key.version }),
      api.listPriorEntryTombstones({ ...key, beforeVersion: key.version }),
    ])
    // Checks run together; the first failure in record order still wins.
    const values = await settleAll([...current, ...prior].map((record) => candidate(key, record)))
    const grouped = new Map<string, Array<Selection>>()

    for (const value of values) {
      const list = grouped.get(value.entryID) ?? []

      list.push(value)
      grouped.set(value.entryID, list)
    }

    return grouped
  }

  const compare = (a: Selection, b: Selection) => {
    return (
      compareRecordDecisionHLC(a.contentHLC, b.contentHLC) ||
      a.keyVersion - b.keyVersion ||
      (a.opHash < b.opHash ? -1 : a.opHash > b.opHash ? 1 : 0)
    )
  }

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

    const sourceVersion = request.sourceVersion ?? key.version
    if (!Number.isInteger(sourceVersion) || sourceVersion < 1 || sourceVersion > key.version)
      throw new VaultNotFound()
    const sourceBranch =
      request.sourceVersion === undefined ? undefined : await ctx.branch(key, sourceVersion, store)
    if (request.sourceVersion !== undefined) {
      const source = await open.open(
        { ...request, atVersion: sourceVersion },
        store,
        sourceBranch?.branchID || undefined,
      )
      source.contentKey.fill(0)
    }
    const revocations =
      request.sourceVersion === undefined || params.mode === 'local'
        ? []
        : await ctx.recordsFor(store).listRevocations(key)
    const wrappingsRead = async () => {
      const existing = await store.listWrappings(key)
      const current = existing.filter(
        (w) =>
          w.keyVersion === sourceVersion &&
          (request.sourceVersion === undefined ||
            params.mode === 'local' ||
            w.provenance === sourceBranch?.branchID),
      )

      return { existing, current, evidence: await ctx.wrappingEvidences(current, store) }
    }
    // Ordered settling keeps the original precedence: branch, then wrapping, then entry failures.
    const [winner, wrappingState, currentSelections] = await settleAll([
      ctx.branch(key, key.version, store),
      wrappingsRead(),
      currentEntries(key, store),
    ])
    const expectedBranches = branches.map((b) => b.branchID)
    const existingWrappings = wrappingState.existing
    const evidence = new Map<string, WrappingEvidence>(
      wrappingState.evidence.map((item) => [item.record.id, item]),
    )
    let retained = wrappingState.current.filter(
      (w) => !excluded(w, [...request.excludedRecipients, ...revocations]),
    )
    if (request.sourceVersion !== undefined && retained.length === 0) throw new VaultNotFound()
    let selections = currentSelections
    let repairNeeded = true
    const keys = new Map<string, Promise<SourceKey>>()
    const pending: Array<Promise<unknown>> = []
    const plaintexts: Array<Uint8Array> = []
    let pinGate: Promise<unknown> = Promise.resolve()
    let generated: Uint8Array | undefined

    try {
      const openSource = (row: EntryRow): Promise<SourceKey> => {
        const run = async (): Promise<SourceKey> => {
          const opened = await open.open(
            { ...request, atVersion: row.keyVersion },
            store,
            params.mode === 'replicated' ? row.provenance : undefined,
          )

          return { contentKey: opened.contentKey, suite: opened.suite }
        }

        if (request.inputs?.pin === undefined) return run()

        // PIN opens stay one at a time: a rejected PIN stops later attempts, spending one try.
        const gated = pinGate.then(run)

        pinGate = gated

        return gated
      }
      const decrypt = (selection: Selection): Promise<Uint8Array | null> => {
        const task = (async () => {
          if (selection.row === undefined) return null

          const row = selection.row
          const identity = JSON.stringify([row.keyVersion, row.provenance])
          let source = keys.get(identity)

          // Cache the promise, not the key: concurrent decrypts must share one open.
          if (source === undefined) {
            source = openSource(row)
            keys.set(identity, source)
          }

          const { contentKey, suite } = await source
          const plaintext = getSuite(suite).decryptEntry({ ...row, contentKey })

          plaintexts.push(plaintext)

          return plaintext
        })()

        pending.push(task)

        return task
      }

      if (repair) {
        const grouped = await candidates(key, store)
        const selected: Array<Selection> = []
        let addsEntry = false
        const comparisons: Array<[Selection, Selection]> = []

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

          comparisons.push([chosen, winning])
        }

        // Plaintext comparisons are independent. Decrypts run together; the first failure in
        // group order wins.
        const compared = await settleAll(
          comparisons.map(([chosen, winning]) => settleAll([decrypt(chosen), decrypt(winning)])),
        )

        for (const [a, b] of compared)
          if (
            (a === null) !== (b === null) ||
            (a !== null && b !== null && (a.length !== b.length || !a.every((v, i) => v === b[i])))
          )
            addsEntry = true

        const signature = (w: WrappingRow) => {
          return JSON.stringify({
            recipient: w.recipientDID,
            factors: factorsFromDescriptors(w.descriptors, request.inputs),
          })
        }
        const winnerRecipients = new Set(
          retained.filter((w) => w.provenance === winner.branchID).map(signature),
        )
        const addsRecipient = retained.some((w) => !winnerRecipients.has(signature(w)))
        let unreadableProjection = false
        const versionBranches = new Map<number, Promise<KeyBranch>>()

        for (const selection of selections) {
          if (selection.row === undefined) continue

          // Selections share few key versions. Read each version's branch once.
          let branch = versionBranches.get(selection.keyVersion)

          if (branch === undefined) {
            branch = ctx.branch(key, selection.keyVersion, store)
            versionBranches.set(selection.keyVersion, branch)
          }

          if (selection.branchID !== (await branch).branchID) {
            unreadableProjection = true
            break
          }
        }

        repairNeeded =
          addsEntry ||
          addsRecipient ||
          unreadableProjection ||
          request.reissue.some(
            (instruction) =>
              instruction.action !== 'preserve' || instruction.contentHLC !== undefined,
          ) ||
          request.excludedRecipients.length !== 0

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

      if (repair && !repairNeeded) return null

      // Opening one alternative does not authenticate secrets on the other retained wrappings.
      for (const previous of retained) {
        if (!previous.descriptors.some((descriptor) => isSecretFactorKind(descriptor.kind)))
          continue

        const verified = await open.open(
          { ...request, atVersion: previous.keyVersion },
          store,
          params.mode === 'replicated' ? previous.provenance : undefined,
          previous.wrappingID,
        )
        verified.contentKey.fill(0)
      }

      const suite = getSuite(request.suite ?? key.suite)
      const next = { ...key, version: key.version + 1, suite: suite.id }

      const contentKey = suite.generateContentKey(params.runtime)

      generated = contentKey

      // Key records and wraps are independent. Wrapping IDs are drawn in retained order.
      const [chain, wrapped] = await settleAll([
        params.mode === 'replicated'
          ? ctx.keyRecords(next, store, undefined, request.consumer)
          : Promise.resolve({ records: [], branchID: '', branchRecordID: '' }),
        settleAll(
          retained.map(async (previous) => {
            const wrappingID = params.runtime.getRandomID()
            const result = await suite.wrap({
              runtime: params.runtime,
              contentKey,
              factors: factorsFromDescriptors(previous.descriptors, request.inputs),
              wrappingID,
              keyID: key.keyID,
              keyVersion: next.version,
              methods: params.methods,
            })

            return { previous, wrappingID, result }
          }),
        ),
      ])
      // Signing stays sequential, so a failed signature stops the rest and a prompting signer is
      // asked nothing after it. HLC allocation and output follow the order: wrappings, entries,
      // then revocations.
      const output: Array<SignedRecord> = [...chain.records]
      const sign = async (task: Promise<SignedRecord>): Promise<void> => {
        output.push(await task)
      }
      const wrappings: Array<WrappingRow> = []

      for (const { previous, wrappingID, result } of wrapped) {
        const row = {
          ...next,
          wrappingID,
          keyVersion: next.version,
          recipientDID: previous.recipientDID,
          provenance: chain.branchID,
          ...result,
        }

        wrappings.push(row)

        if (params.mode === 'replicated') {
          const prior = evidence.get(previous.wrappingID)

          if (prior === undefined) throw new VaultNotFound()

          await sign(
            records.wrapping(
              row,
              chain,
              request.consumer === undefined ? prior.op.claim.meta.consumer : request.consumer,
              await params.nextHLC(),
            ),
          )
        }
      }

      const entries: Array<EntryRow> = []
      const deletions: Array<string> = []

      const reissued = selections.map((selected) => {
        const instruction = instructions.get(selected.entryID)
        const deleting =
          instruction?.action === 'delete' ||
          (selected.row === undefined && instruction?.action !== 'replace')
        const decrypting =
          instruction?.action === 'skip' || deleting || instruction?.action === 'replace'
            ? undefined
            : decrypt(selected)

        // Awaited in selection order below. An earlier failure must not surface as unhandled.
        decrypting?.catch(() => {})

        return { selected, instruction, deleting, decrypting }
      })

      for (const { selected, instruction, deleting, decrypting } of reissued) {
        if (instruction?.action === 'skip') continue

        const contentHLC = instruction?.contentHLC ?? selected.contentHLC
        const consumer =
          instruction !== undefined && Object.hasOwn(instruction, 'consumer')
            ? instruction.consumer
            : selected.consumer
        const hlc = await params.nextHLC()

        if (deleting) {
          deletions.push(selected.entryID)

          if (params.mode === 'replicated')
            await sign(
              ctx.signed(
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
          instruction?.action === 'replace' ? instruction.plaintext : await decrypting

        if (plaintext === null || selected.row === undefined) throw new VaultRepairPending()

        const encrypted = suite.encryptEntry({
          runtime: params.runtime,
          contentKey,
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
          await sign(records.entry(row, chain, contentHLC, consumer))
      }

      if (params.mode === 'replicated') {
        for (const did of new Set(request.excludedRecipients)) {
          const id = vaultRevocationRecordID(key.keyID, did)
          const revokedDID = id.slice(id.indexOf('/') + 1)

          await sign(
            ctx.signed(
              'vault.revocation',
              { ownerDID: key.ownerDID, id },
              {},
              { keyID: key.keyID, revokedDID, consumer: request.consumer ?? null },
              await params.nextHLC(),
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
        // Each set names distinct rows, so the batched writes run together. The first failure in
        // the old order wins.
        await settleAll([
          store.putWrappings(wrappings),
          store.putEntries(entries),
          store.deleteEntries(deletions.map((entryID) => ({ ownerDID: key.ownerDID, entryID }))),
          store.deleteWrappings(
            existingWrappings.filter((w) => excluded(w, request.excludedRecipients)),
          ),
        ])
      }

      return next.version
    } finally {
      // Let every started decrypt settle first, so no key or plaintext arrives after zeroing.
      await Promise.allSettled(pending)

      for (const source of await Promise.allSettled(keys.values()))
        if (source.status === 'fulfilled') source.value.contentKey.fill(0)

      for (const plaintext of plaintexts) plaintext.fill(0)
      generated?.fill(0)
    }
  }

  async function rotate(request: RotateKeyParams): Promise<number> {
    await ctx.authorize('rotate', 'administer', request)

    const observed = request.sourceVersion === undefined ? undefined : await ctx.key(request)
    const version = await ctx.locked([request], async (tx) => {
      if (observed !== undefined && (await ctx.key(request, tx)).version !== observed.version)
        throw new VaultWriteConflict()
      if (request.sourceVersion !== undefined)
        await ctx.authorize('rotate', 'administer', request, tx)
      return rotateLocked(request, tx, false)
    })

    if (version === null) throw new VaultNotFound()

    ctx.evict(request)

    return version
  }

  async function repairFork(request: RotateKeyParams): Promise<ForkRepairResult> {
    await ctx.authorize('repairFork', 'administer', request)

    if (params.mode === 'local') return { status: 'not-needed' }

    try {
      const version = await ctx.locked([request], async (tx) => {
        // A projection naming the wrong record refuses every branch read as pending. Rebuild it
        // from the signed records first, so repair sees the key's real branches.
        await ctx.recordsFor(tx).rebuildKeyBranches(request)

        return rotateLocked(request, tx, true)
      })

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
