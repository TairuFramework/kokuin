import type { SignedRecord } from '@kokuin/records'
import {
  createVaultKeyReference,
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
import type { KeyAddress, KeyRow, WrappingRow } from './types.js'

export function createVaultCoordinator(params: VaultCoordinatorParams): VaultCoordinator {
  const ctx = createCoordinatorContext(params)
  const open = createOpenFunctions(ctx)
  const records = createRecordFunctions(ctx)
  const rotate = createRotateFunctions(ctx, open, records)
  const entries = createEntryFunctions(ctx, open, records)

  async function createKey(request: CreateKeyParams): Promise<KeyAddress> {
    await ctx.authorize('createKey', 'administer', request)
    const unique = params.runtime.getRandomValues(new Uint8Array(16))
    const { keyID, keyUnique } = createVaultKeyReference(request.ownerDID, unique)
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
    const contentKey = suite.generateContentKey(params.runtime)
    try {
      await ctx.locked([key], async (store) => {
        if ((await store.getKey(key)) !== undefined) throw new VaultWriteConflict()
        const chain =
          params.mode === 'replicated'
            ? await ctx.keyRecords(key, store, keyUnique, request.consumer)
            : { records: [], branchID: '', branchRecordID: '' }
        const output: Array<SignedRecord> = [...chain.records]
        const rows: Array<WrappingRow> = []
        for (const factors of wrappings) {
          const wrappingID = params.runtime.getRandomID()
          const wrapped = await suite.wrap({
            runtime: params.runtime,
            contentKey,
            factors,
            wrappingID,
            keyID: key.keyID,
            keyVersion: 1,
            methods: params.methods,
          })
          const did = recipientDIDForFactors(factors)
          const row = {
            ...key,
            wrappingID,
            keyVersion: 1,
            recipientDID: did,
            provenance: chain.branchID,
            ...wrapped,
          }
          rows.push(row)
          if (params.mode === 'replicated')
            output.push(await records.wrapping(row, chain, request.consumer ?? null))
        }
        if (params.mode === 'replicated')
          await ctx.write(
            store,
            output,
            { key: { ...key, expectedVersion: null, expectedBranches: [] } },
            request,
          )
        else {
          await store.putKey(key)
          for (const row of rows) await store.putWrapping(row)
        }
      })
      return { ownerDID: key.ownerDID, keyID: key.keyID }
    } finally {
      contentKey.fill(0)
    }
  }
  async function rewrap(
    request: OpenKeyParams,
    change: (
      factors: ReturnType<typeof factorsFromDescriptors>,
    ) => ReturnType<typeof factorsFromDescriptors>,
  ) {
    await ctx.locked([request], async (store) => {
      const key = await ctx.key(request, store)
      const branch = await ctx.branch(request, key.version, store)
      const rows = (await store.listWrappings({ ...key, keyVersion: key.version })).filter(
        (w) =>
          (params.mode === 'local' || w.provenance === branch.branchID) &&
          w.descriptors.some((d) => d.kind === 'did') &&
          satisfiableFactors(w.descriptors, params.identity) !== null,
      )
      if (rows.length !== 1) throw new VaultNotFound()
      const existing = rows[0]
      if (existing === undefined) throw new VaultNotFound()
      if (request.atVersion !== undefined && request.atVersion !== key.version)
        throw new VaultWriteConflict()
      await ctx.wrappingEvidence(existing, store)
      const opened = await open.open({ ...request, atVersion: key.version }, store)
      try {
        const wrappingID = params.runtime.getRandomID()
        const factors = change(factorsFromDescriptors(existing.descriptors, request.inputs))
        const wrapped = await getSuite(opened.suite).wrap({
          runtime: params.runtime,
          contentKey: opened.contentKey,
          factors,
          wrappingID,
          keyID: key.keyID,
          keyVersion: key.version,
          methods: params.methods,
        })
        const row = {
          ...existing,
          wrappingID,
          ...wrapped,
          recipientDID: recipientDIDForFactors(factors),
        }
        if (params.mode === 'local') {
          await store.putWrapping(row)
          await store.deleteWrapping(existing)
        } else {
          const previous = await ctx.stored(
            { type: 'vault.wrapping', owner: key.ownerDID, id: existing.wrappingID },
            store,
          )
          const replacement = await records.wrapping(row, branch, previous.op.claim.meta.consumer)
          const deletion = await ctx.signed(
            'vault.wrapping',
            { ownerDID: key.ownerDID, id: existing.wrappingID },
            null,
            {
              keyID: key.keyID,
              keyVersion: key.version,
              recipient: existing.recipientDID,
              consumer: previous.op.claim.meta.consumer,
            },
          )
          await ctx.write(
            store,
            [replacement, deletion],
            {
              key: {
                ...key,
                expectedVersion: key.version,
                expectedBranches: (await ctx.branches(key, key.version, store)).map(
                  (b) => b.branchID,
                ),
              },
            },
            request,
          )
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
      await ctx.authorize('openKey', 'read', request)
      return open.open(request)
    },
    async unlock(request) {
      await ctx.authorize('unlock', 'read', request)
      ;(await open.open(request)).contentKey.fill(0)
    },
    async lock(address) {
      await ctx.authorize('lock', 'read', address)
      ctx.evict(address)
    },
    async lockAll(ownerDID, call = {}) {
      await ctx.authorize('lockAll', 'read', { ownerDID, ...call })
      ctx.evictAll(ownerDID)
    },
    async status(request): Promise<KeyStatus> {
      await ctx.authorize('status', 'read', request)
      const key = await ctx.key(request)
      if (!isSupportedSuite(key.suite)) return { state: 'unopenable' }
      const version = request.atVersion ?? key.version
      if (await open.revoked(request, params.store)) {
        ctx.evict(request)
        return { state: 'unopenable' }
      }
      const branch = await ctx.branch(request, version)
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
      await ctx.authorize('listKeys', 'read', { ownerDID, ...call })
      return params.store.listKeys(ownerDID)
    },
    async setKeyState(request) {
      await ctx.authorize('setKeyState', 'administer', request)
      await ctx.locked([request], async (store) => {
        const key = await ctx.key(request, store)
        if (params.mode === 'local') {
          await store.setKeyState(request)
          return
        }
        const previous = await ctx.stored(
          { type: 'vault.key', owner: key.ownerDID, id: key.keyID },
          store,
        )
        const record = await ctx.signed(
          'vault.key',
          { ownerDID: key.ownerDID, id: key.keyID },
          { suite: key.suite, state: request.state },
          {
            ...previous.op.claim.meta,
            keyID: key.keyID,
            keyUnique: previous.op.claim.meta.keyUnique as string,
            version: key.version,
            state: request.state,
            consumer: previous.op.claim.meta.consumer,
          },
        )
        await ctx.write(store, [record], { key: { ...key, expectedVersion: key.version } }, request)
      })
      ctx.evict(request)
    },
    async deleteKey(request) {
      await ctx.authorize('deleteKey', 'administer', request)
      await ctx.locked([request], async (store) => {
        const key = await ctx.key(request, store)
        if (params.mode === 'local') {
          await store.deleteKey(request)
          return
        }
        const previous = await ctx.stored(
          { type: 'vault.key', owner: key.ownerDID, id: key.keyID },
          store,
        )
        const keyUnique = previous.op.claim.meta.keyUnique
        if (typeof keyUnique !== 'string') throw new VaultNotFound()
        const record = await ctx.signed(
          'vault.key',
          { ownerDID: key.ownerDID, id: key.keyID },
          null,
          {
            keyID: key.keyID,
            keyUnique,
            version: key.version,
            state: 'deleted',
            consumer: previous.op.claim.meta.consumer,
          },
        )
        await ctx.write(store, [record], { key: { ...key, expectedVersion: key.version } }, request)
      })
      ctx.evict(request)
    },
    async grant(request) {
      await ctx.authorize('grant', 'administer', request)
      await ctx.locked([request], async (store) => {
        const key = await ctx.key(request, store)
        if (
          params.mode === 'replicated' &&
          (await ctx.recordsFor(store).listRevocations(request)).some(
            (did) =>
              vaultRevocationRecordID(key.keyID, did) ===
              vaultRevocationRecordID(key.keyID, request.recipientDID),
          )
        )
          throw new VaultNotFound()
        if (request.atVersion !== undefined && request.atVersion !== key.version)
          throw new VaultWriteConflict()
        const opened = await open.open({ ...request, atVersion: key.version }, store)
        try {
          const wrappingID = params.runtime.getRandomID()
          const wrapped = await getSuite(opened.suite).wrap({
            runtime: params.runtime,
            contentKey: opened.contentKey,
            factors: [{ kind: 'did', recipientDID: request.recipientDID }],
            wrappingID,
            keyID: key.keyID,
            keyVersion: key.version,
            methods: params.methods,
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
            const branch = await ctx.branch(key, key.version, store)
            await ctx.write(
              store,
              [await records.wrapping(row, branch)],
              {
                key: {
                  ...key,
                  expectedVersion: key.version,
                  expectedBranches: (await ctx.branches(key, key.version, store)).map(
                    (b) => b.branchID,
                  ),
                },
              },
              request,
            )
          }
        } finally {
          opened.contentKey.fill(0)
        }
      })
    },
    async addFactor(request) {
      await ctx.authorize('addFactor', 'administer', request)
      await rewrap(request, (factors) => [...factors, request.factor])
    },
    async removeFactor(request) {
      await ctx.authorize('removeFactor', 'administer', request)
      await rewrap(request, (factors) => {
        if (!factors.some((f) => f.kind === request.kind)) throw new VaultNotFound()
        return factors.filter((f) => f.kind !== request.kind)
      })
    },
    async readEntry(request) {
      await ctx.authorize('readEntry', 'read', request)
      return ctx.read(async (store) => {
        const row = await store.getEntry(request)
        if (row === undefined) throw new VaultNotFound()
        await ctx.authorize('readEntry', 'read', { ...request, keyID: row.keyID }, store)
        await records.entryInfo(row, store)
        return open.decrypt(row, { ...row, inputs: request.inputs }, store)
      })
    },
    async getEntry(request) {
      await ctx.authorize('getEntry', 'read', request)
      return params.store.getEntry(request)
    },
    async listEntries(request) {
      await ctx.authorize('listEntries', 'read', request)
      return params.store.listEntries(request)
    },
    ...entries,
    ...rotate,
    reendorse: records.reendorse,
  }
  return coordinator
}
