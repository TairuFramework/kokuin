import type { SignedRecord } from '@kokuin/records'
import { compareRecordDecisionHLC } from '@kokuin/records'
import type { FactorInput } from '@kokuin/vault'
import {
  createVaultKeyReference,
  decodeVaultRecord,
  factorsFromDescriptors,
  getSuite,
  isSupportedSuite,
  recipientDIDForFactors,
  satisfiableFactors,
  vaultRevocationRecordID,
} from '@kokuin/vault'

import { createCoordinatorContext, VaultNotFound } from './coordinator-context.js'
import { createEntryFunctions } from './coordinator-entries.js'
import { createOpenFunctions } from './coordinator-open.js'
import { createRecordFunctions } from './coordinator-records.js'
import { createRotateFunctions } from './coordinator-rotate.js'
import type {
  CreateKeyParams,
  KeyStatus,
  OpenKeyParams,
  VaultCoordinator,
  VaultCoordinatorParams,
} from './coordinator-types.js'
import { VaultWriteConflict } from './record-context.js'
import { settleAll, settledValue } from './settle.js'
import { snapshotCall } from './snapshot.js'
import type { KeyAddress, KeyRow, WrappingRow } from './types.js'

export function createVaultCoordinator(input: VaultCoordinatorParams): VaultCoordinator {
  const ctx = createCoordinatorContext(input)
  const params = ctx.params
  const open = createOpenFunctions(ctx)
  const records = createRecordFunctions(ctx)
  const rotate = createRotateFunctions(ctx, open, records)
  const entries = createEntryFunctions(ctx, open, records)

  async function createKey(input: CreateKeyParams): Promise<KeyAddress> {
    const request = snapshotCall(input)
    await ctx.authorize({ operation: 'createKey', verb: 'administer', address: request })

    const unique = params.runtime.getRandomValues(new Uint8Array(16))
    const { keyID, keyUnique } = await createVaultKeyReference(request.ownerDID, unique, params)
    const key: KeyRow = {
      ownerDID: request.ownerDID,
      keyID,
      version: 1,
      suite: request.suite ?? 1,
      state: 'active',
    }
    const suite = getSuite(key.suite)
    let wrappings = request.wrappings

    if (wrappings === undefined) {
      if (params.identity === null)
        throw new TypeError('An explicit wrapping or agreement identity is required')

      const recipientDID =
        'longForm' in params.identity && typeof params.identity.longForm === 'string'
          ? params.identity.longForm
          : params.identity.id

      wrappings = [[{ kind: 'did', recipientDID }]]
    }

    if (wrappings.length === 0) throw new TypeError('At least one wrapping is required')

    const factorSets = wrappings
    const contentKey = suite.generateContentKey(params.runtime)

    try {
      await ctx.locked([key], async (store) => {
        if ((await store.getKey(key)) !== undefined) throw new VaultWriteConflict()

        // Key records and wraps are independent. Wrapping IDs are drawn in factor-set order.
        const [chain, wrapped] = await settleAll([
          params.mode === 'replicated'
            ? ctx.keyRecords({
                row: key,
                store: store,
                unique: keyUnique,
                consumer: request.consumer,
              })
            : Promise.resolve({ records: [], branchID: '', branchRecordID: '' }),
          settleAll(
            factorSets.map(async (factors) => {
              const wrappingID = params.runtime.getRandomID()
              const result = await suite.wrap({
                crypto: params.crypto,
                runtime: params.runtime,
                contentKey,
                factors,
                wrappingID,
                keyID: key.keyID,
                keyVersion: 1,
                methods: ctx.methodsFor(store),
              })

              return { factors, wrappingID, result }
            }),
          ),
        ])
        const rows: Array<WrappingRow> = wrapped.map(({ factors, wrappingID, result }) => {
          return {
            ...key,
            wrappingID,
            keyVersion: 1,
            recipientDID: recipientDIDForFactors(factors),
            provenance: chain.branchID,
            ...result,
          }
        })

        if (params.mode === 'replicated') {
          const output: Array<SignedRecord> = [...chain.records]

          // Signing stays sequential: a failure stops the rest. HLC allocation and output order
          // follow the factor sets.
          for (const row of rows)
            output.push(
              await records.wrapping({
                row: row,
                branch: chain,
                consumer: request.consumer ?? null,
              }),
            )

          await ctx.write({
            store: store,
            output: output,
            preconditions: { key: { ...key, expectedVersion: null, expectedBranches: [] } },
            call: request,
          })
        } else {
          await store.putKey(key)
          await store.putWrappings(rows)
        }
      })

      return { ownerDID: key.ownerDID, keyID: key.keyID }
    } finally {
      contentKey.fill(0)
    }
  }

  async function rewrap(
    request: OpenKeyParams & { consumer?: unknown },
    change: (factors: Array<FactorInput>) => Array<FactorInput>,
  ): Promise<void> {
    await ctx.locked([request], async (store) => {
      const key = await ctx.key(request, store)
      const [branch, branches, wrappings] = await settleAll([
        ctx.branch({ address: request, version: key.version, store: store }),
        ctx.branches(key, key.version, store),
        store.listWrappings({ ...key, keyVersion: key.version }),
      ])
      const rows = wrappings.filter((w) => {
        return (
          (params.mode === 'local' || w.provenance === branch.branchID) &&
          w.descriptors.some((d) => d.kind === 'did') &&
          satisfiableFactors(w.descriptors, params.identity) !== null
        )
      })

      if (rows.length !== 1) throw new VaultNotFound()

      const existing = rows[0]

      if (existing === undefined) throw new VaultNotFound()

      if (request.atVersion !== undefined && request.atVersion !== key.version)
        throw new VaultWriteConflict()

      const evidence = await ctx.wrappingEvidence(existing, store)
      const opened = await open.open({
        address: { ...request, atVersion: key.version },
        store: store,
      })

      try {
        const wrappingID = params.runtime.getRandomID()
        const factors = change(factorsFromDescriptors(existing.descriptors, request.inputs))
        const wrapped = await getSuite(opened.suite).wrap({
          crypto: params.crypto,
          runtime: params.runtime,
          contentKey: opened.contentKey,
          factors,
          wrappingID,
          keyID: key.keyID,
          keyVersion: key.version,
          methods: ctx.methodsFor(store),
        })
        const row = {
          ...existing,
          wrappingID,
          ...wrapped,
          recipientDID: recipientDIDForFactors(factors),
        }

        if (params.mode === 'local') {
          // Different wrapping IDs: the write and the delete are independent.
          await settleAll([store.putWrapping(row), store.deleteWrapping(existing)])
        } else {
          // The verified evidence already holds the prior wrapping's authenticated metadata.
          if (evidence === undefined) throw new VaultNotFound()

          const consumer =
            request.consumer === undefined ? evidence.op.claim.meta.consumer : request.consumer
          const replacement = await records.wrapping({
            row: row,
            branch: branch,
            consumer: consumer,
          })
          const deletion = await ctx.signed({
            type: 'vault.wrapping',
            address: { ownerDID: key.ownerDID, id: existing.wrappingID },
            payload: null,
            meta: {
              keyID: key.keyID,
              keyVersion: key.version,
              recipient: existing.recipientDID,
              consumer,
            },
          })

          await ctx.write({
            store: store,
            output: [replacement, deletion],
            preconditions: {
              key: {
                ...key,
                expectedVersion: key.version,
                expectedBranches: branches.map((b) => b.branchID),
              },
            },
            call: request,
          })
        }
      } finally {
        opened.contentKey.fill(0)
      }
    })

    ctx.evict(request)
  }

  const coordinator: VaultCoordinator = {
    get records() {
      if (ctx.records === undefined) throw new TypeError('Local coordinator has no records path')

      return ctx.records
    },
    createKey,
    async openKey(request) {
      await ctx.authorize({ operation: 'openKey', verb: 'read', address: request })

      return open.open({ address: request })
    },
    async unlock(request) {
      await ctx.authorize({ operation: 'unlock', verb: 'read', address: request })

      const opened = await open.open({ address: request })

      opened.contentKey.fill(0)
    },
    async lock(address) {
      await ctx.authorize({ operation: 'lock', verb: 'read', address: address })
      ctx.evict(address)
    },
    async lockAll(ownerDID, call = {}) {
      await ctx.authorize({ operation: 'lockAll', verb: 'read', address: { ownerDID, ...call } })
      ctx.evictAll(ownerDID)
    },
    async status(request): Promise<KeyStatus> {
      await ctx.authorize({ operation: 'status', verb: 'read', address: request })

      // Both reads run together. Their results are checked in the old order: key, suite, revocation.
      const [keyRead, revokedRead] = await Promise.allSettled([
        ctx.key(request),
        open.revoked(request, params.store),
      ])
      const key = settledValue(keyRead)

      if (!isSupportedSuite(key.suite)) return { state: 'unopenable' }

      const version = request.atVersion ?? key.version

      if (settledValue(revokedRead)) {
        ctx.evict(request)

        return { state: 'unopenable' }
      }

      const branch = await ctx.branch({ address: request, version: version })
      const hit = ctx.cache.get(ctx.cacheID(request), version)

      if (hit !== null) {
        const matches = hit.branchID === branch.branchID

        hit.contentKey.fill(0)

        if (matches) return { state: 'unlocked' }
      }

      const options = (await params.store.listWrappings({ ...request, keyVersion: version }))
        .filter((w) => params.mode === 'local' || w.provenance === branch.branchID)
        .map((w) => satisfiableFactors(w.descriptors, params.identity))
        .filter((value) => value !== null)

      if (options.some((o) => o.length === 0)) return { state: 'available' }

      return options.length > 0
        ? { state: 'locked', unlockOptions: options }
        : { state: 'unopenable' }
    },
    async listKeys(ownerDID, call = {}) {
      await ctx.authorize({ operation: 'listKeys', verb: 'read', address: { ownerDID, ...call } })

      return params.store.listKeys(ownerDID)
    },
    async setKeyState(input) {
      const request = snapshotCall(input)
      await ctx.authorize({ operation: 'setKeyState', verb: 'administer', address: request })
      await ctx.locked([request], async (store) => {
        if (params.mode === 'local') {
          await ctx.key(request, store)
          await store.setKeyState(request)

          return
        }

        const [key, previous] = await settleAll([
          ctx.key(request, store),
          ctx.stored({ type: 'vault.key', owner: request.ownerDID, id: request.keyID }, store),
        ])
        const record = await ctx.signed({
          type: 'vault.key',
          address: { ownerDID: key.ownerDID, id: key.keyID },
          payload: { suite: key.suite, state: request.state },
          meta: {
            ...previous.op.claim.meta,
            keyID: key.keyID,
            keyUnique: previous.op.claim.meta.keyUnique as string,
            version: key.version,
            state: request.state,
            consumer:
              request.consumer === undefined ? previous.op.claim.meta.consumer : request.consumer,
          },
        })

        await ctx.write({
          store: store,
          output: [record],
          preconditions: { key: { ...key, expectedVersion: key.version } },
          call: request,
        })
      })

      ctx.evict(request)
    },
    async deleteKey(input) {
      const request = snapshotCall(input)
      await ctx.authorize({ operation: 'deleteKey', verb: 'administer', address: request })
      await ctx.locked([request], async (store) => {
        if (params.mode === 'local') {
          await ctx.key(request, store)
          await store.deleteKey(request)

          return
        }

        const [key, previous] = await settleAll([
          ctx.key(request, store),
          ctx.stored({ type: 'vault.key', owner: request.ownerDID, id: request.keyID }, store),
        ])
        const keyUnique = previous.op.claim.meta.keyUnique

        if (typeof keyUnique !== 'string') throw new VaultNotFound()

        const record = await ctx.signed({
          type: 'vault.key',
          address: { ownerDID: key.ownerDID, id: key.keyID },
          payload: null,
          meta: {
            keyID: key.keyID,
            keyUnique,
            version: key.version,
            state: 'deleted',
            consumer:
              request.consumer === undefined ? previous.op.claim.meta.consumer : request.consumer,
          },
        })

        await ctx.write({
          store: store,
          output: [record],
          preconditions: { key: { ...key, expectedVersion: key.version } },
          call: request,
        })
      })

      ctx.evict(request)
    },
    async grant(input) {
      const request = snapshotCall(input)
      await ctx.authorize({ operation: 'grant', verb: 'administer', address: request })
      await ctx.locked([request], async (store) => {
        const [key, revocations] = await settleAll([
          ctx.key(request, store),
          params.mode === 'replicated'
            ? ctx.recordsFor(store).listRevocations(request)
            : Promise.resolve([]),
        ])

        if (
          revocations.some((did) => {
            return (
              vaultRevocationRecordID(key.keyID, did) ===
              vaultRevocationRecordID(key.keyID, request.recipientDID)
            )
          })
        )
          throw new VaultNotFound()

        if (request.atVersion !== undefined && request.atVersion !== key.version)
          throw new VaultWriteConflict()

        const opened = await open.open({
          address: { ...request, atVersion: key.version },
          store: store,
        })

        try {
          const wrappingID = params.runtime.getRandomID()
          const wrapped = await getSuite(opened.suite).wrap({
            crypto: params.crypto,
            runtime: params.runtime,
            contentKey: opened.contentKey,
            factors: [{ kind: 'did', recipientDID: request.recipientDID }],
            wrappingID,
            keyID: key.keyID,
            keyVersion: key.version,
            methods: ctx.methodsFor(store),
          })
          const row = {
            ...key,
            wrappingID,
            keyVersion: key.version,
            recipientDID: recipientDIDForFactors([
              { kind: 'did', recipientDID: request.recipientDID },
            ]),
            provenance: opened.branchID,
            ...wrapped,
          }

          if (params.mode === 'local') await store.putWrapping(row)
          else {
            const [branch, branches] = await settleAll([
              ctx.branch({ address: key, version: key.version, store: store }),
              ctx.branches(key, key.version, store),
            ])
            const record = await records.wrapping({
              row: row,
              branch: branch,
              consumer: request.consumer,
            })

            await ctx.write({
              store: store,
              output: [record],
              preconditions: {
                key: {
                  ...key,
                  expectedVersion: key.version,
                  expectedBranches: branches.map((b) => b.branchID),
                },
              },
              call: request,
            })
          }
        } finally {
          opened.contentKey.fill(0)
        }
      })
    },
    async refreshWrapping(input) {
      const request = snapshotCall(input)
      await ctx.authorize({ operation: 'refreshWrapping', verb: 'administer', address: request })
      if (params.mode !== 'replicated')
        throw new TypeError('Wrapping refresh requires replicated mode')
      return ctx.locked([request], async (store) => {
        await ctx.authorize({
          operation: 'refreshWrapping',
          verb: 'administer',
          address: request,
          store: store,
        })
        const key = await ctx.key(request, store)
        const row = await store.getWrapping(request)
        if (
          row === undefined ||
          row.keyID !== key.keyID ||
          row.keyVersion !== key.version ||
          key.state !== 'active'
        )
          throw new VaultNotFound()
        const [branch, branches, evidence, revocations] = await settleAll([
          ctx.branch({ address: key, version: key.version, store: store }),
          ctx.branches(key, key.version, store),
          ctx.wrappingEvidence(row, store),
          ctx.recordsFor(store).listRevocations(key),
        ])
        if (
          row.provenance !== branch.branchID ||
          evidence === undefined ||
          (await open.revoked(request, store))
        )
          throw new VaultNotFound()
        const recipients = [
          row.recipientDID,
          ...row.descriptors.filter((d) => d.kind === 'did').map((d) => d.params.recipient),
        ]
        if (
          revocations.some((did) => {
            return recipients.some((recipient) => {
              return (
                typeof recipient === 'string' &&
                vaultRevocationRecordID(key.keyID, recipient) ===
                  vaultRevocationRecordID(key.keyID, did)
              )
            })
          })
        )
          throw new VaultNotFound()
        if (evidence.record.opHash !== request.expectedOpHash) throw new VaultWriteConflict()
        const decoded = await decodeVaultRecord(evidence.record, evidence.op.claim.meta, params)
        if (decoded.type !== 'vault.wrapping') throw new VaultNotFound()
        const hlc = await params.nextHLC()
        if (compareRecordDecisionHLC(hlc, evidence.record.hlc) <= 0) throw new VaultWriteConflict()
        const record = await ctx.signed({
          type: 'vault.wrapping',
          address: { ownerDID: key.ownerDID, id: row.wrappingID },
          payload: decoded.payload,
          meta: { ...decoded.meta, consumer: request.consumer },
          hlc: hlc,
        })
        await ctx.write({
          store: store,
          output: [record],
          preconditions: {
            key: {
              ...key,
              expectedVersion: key.version,
              expectedBranches: branches.map((b) => b.branchID),
            },
            copy: {
              type: record.type,
              owner: record.owner,
              id: record.id,
              expectedOpHash: request.expectedOpHash,
            },
          },
          call: request,
        })
        if (await open.revoked(request, store)) throw new VaultNotFound()
        return record
      })
    },
    async addFactor(input) {
      const request = snapshotCall(input)
      await ctx.authorize({ operation: 'addFactor', verb: 'administer', address: request })
      await rewrap(request, (factors) => [...factors, request.factor])
    },
    async removeFactor(input) {
      const request = snapshotCall(input)
      await ctx.authorize({ operation: 'removeFactor', verb: 'administer', address: request })
      await rewrap(request, (factors) => {
        if (!factors.some((f) => f.kind === request.kind)) throw new VaultNotFound()

        return factors.filter((f) => f.kind !== request.kind)
      })
    },
    async readEntry(request) {
      await ctx.authorize({ operation: 'readEntry', verb: 'read', address: request })

      return ctx.read(async (store) => {
        const row = await store.getEntry(request)

        if (row === undefined) throw new VaultNotFound()

        await ctx.authorize({
          operation: 'readEntry',
          verb: 'read',
          address: { ...request, keyID: row.keyID },
          store: store,
        })
        await records.entryInfo(row, store)

        let specific = false
        if (params.mode === 'replicated' && params.authorizeEquivalentBranch !== undefined) {
          const winning = await ctx.branch({ address: row, version: row.keyVersion, store: store })
          if (winning.branchID !== row.provenance) {
            const own = await ctx.branch({
              address: row,
              version: row.keyVersion,
              store: store,
              specific: row.provenance,
            })
            const [entry, entryBranch, winningBranch] = await ctx.storedMany(
              [
                { type: 'vault.entry', owner: row.ownerDID, id: row.entryID },
                { type: 'vault.key-branch', owner: row.ownerDID, id: own.branchRecordID },
                { type: 'vault.key-branch', owner: row.ownerDID, id: winning.branchRecordID },
              ],
              store,
            )
            if (!entry || !entryBranch || !winningBranch) throw new VaultNotFound()
            specific =
              (await params.authorizeEquivalentBranch({
                entry: entry.record,
                entryBranch: entryBranch.record,
                winningBranch: winningBranch.record,
              })) === true
          }
        }
        return open.decrypt({
          row: row,
          address: { ...row, inputs: request.inputs },
          store: store,
          specific: specific,
        })
      })
    },
    async getEntry(request) {
      await ctx.authorize({ operation: 'getEntry', verb: 'read', address: request })

      return params.store.getEntry(request)
    },
    async listEntries(request) {
      await ctx.authorize({ operation: 'listEntries', verb: 'read', address: request })

      return params.store.listEntries(request)
    },
    ...entries,
    ...rotate,
    reendorse: records.reendorse,
  }

  return coordinator
}
