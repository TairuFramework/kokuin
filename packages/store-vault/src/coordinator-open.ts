import {
  createPinThrottle,
  getSuite,
  NoAvailableFactor,
  satisfiableFactors,
  VaultPinRejected,
  VaultSecretRejected,
  VaultTampered,
  vaultRevocationRecordID,
} from '@kokuin/vault'

import type { CoordinatorContext } from './coordinator-context.js'
import {
  VaultKeyLocked,
  VaultNotFound,
  VaultRepairPending,
  VaultSupersededBranch,
} from './coordinator-context.js'
import type { OpenedKey, OpenKeyParams } from './coordinator-types.js'
import type { EntryRow, VaultStoreAPI } from './types.js'

export type OpenFunctions = {
  open(address: OpenKeyParams, store?: VaultStoreAPI, specific?: string): Promise<OpenedKey>
  decrypt(
    row: EntryRow | undefined,
    address: OpenKeyParams,
    store?: VaultStoreAPI,
    specific?: boolean,
  ): Promise<Uint8Array>
  revoked(address: OpenKeyParams, store: VaultStoreAPI): Promise<boolean>
}

export function createOpenFunctions(ctx: CoordinatorContext): OpenFunctions {
  const { params, cache, cacheID } = ctx
  const throttle = createPinThrottle(params.pinThrottle)
  const inFlight = new Map<string, Promise<void>>()

  async function revoked(address: OpenKeyParams, store: VaultStoreAPI) {
    if (params.mode !== 'replicated') return false

    const denied = await ctx.recordsFor(store).listRevocations(address)

    return denied.some((did) => {
      return (
        vaultRevocationRecordID(address.keyID, did) ===
        vaultRevocationRecordID(address.keyID, params.principal)
      )
    })
  }

  async function doOpen(
    address: OpenKeyParams,
    store: VaultStoreAPI,
    generation: string,
    specific?: string,
  ): Promise<OpenedKey> {
    const key = await ctx.key(address, store)
    const version = address.atVersion ?? key.version

    if (version > key.version || version < 1) throw new VaultNotFound()

    if (await revoked(address, store)) {
      ctx.evict(address)

      throw new VaultNotFound()
    }

    const branch = await ctx.branch(address, version, store, specific)
    const supplied = Object.values(address.inputs ?? {}).some((input) => input !== undefined)

    if (!supplied) {
      const hit = cache.get(cacheID(address), version)

      if (hit !== null) {
        if (hit.branchID === branch.branchID) return { ...hit, version, suite: branch.suite }

        hit.contentKey.fill(0)
        cache.evictVersion(cacheID(address), version)
      }
    }

    const wrappings = await store.listWrappings({ ...address, keyVersion: version })
    let rejected: VaultSecretRejected | undefined
    let locked = false

    for (const row of wrappings) {
      if (params.mode === 'replicated' && row.provenance !== branch.branchID) continue

      const needed = satisfiableFactors(row.descriptors, params.identity)

      if (needed === null) continue

      const evidence = await ctx.wrappingEvidence(row, store)
      const expectedDescriptorDigest = evidence?.expectedDescriptorDigest

      try {
        const contentKey = await getSuite(branch.suite).unwrap({
          ...row,
          identity: params.identity,
          inputs: address.inputs,
          expectedDescriptorDigest,
        })

        if (ctx.generation(address) === generation && specific === undefined)
          cache.set(cacheID(address), contentKey, version, branch.branchID)

        return { contentKey, version, suite: branch.suite, branchID: branch.branchID }
      } catch (error) {
        if (error instanceof VaultTampered) throw error

        if (error instanceof VaultSecretRejected) rejected = error
        else if (error instanceof NoAvailableFactor && needed.length > 0) locked = true
        else throw error
      }
    }

    if (rejected !== undefined) throw rejected

    if (locked) throw new VaultKeyLocked()

    if (
      params.mode === 'replicated' &&
      wrappings.some((w) => {
        return (
          w.provenance !== branch.branchID &&
          satisfiableFactors(w.descriptors, params.identity) !== null
        )
      })
    )
      throw new VaultRepairPending()

    throw new VaultNotFound()
  }

  async function open(
    address: OpenKeyParams,
    store = params.store,
    specific?: string,
  ): Promise<OpenedKey> {
    const generation = ctx.generation(address)

    if (address.inputs?.pin !== undefined) {
      const id = cacheID(address)
      const rejected = (cause?: unknown) => {
        return new VaultPinRejected(address.keyID, {
          cause,
          attemptsRemaining: throttle.attemptsRemaining(id),
          retryAfter: throttle.retryAfter(id),
        })
      }

      if (throttle.retryAfter(id) > 0) throw rejected()

      try {
        const opened = await doOpen(address, store, generation, specific)

        throttle.recordSuccess(id)

        return opened
      } catch (error) {
        if (error instanceof VaultSecretRejected) {
          throttle.recordFailure(id)

          throw rejected(error)
        }

        throw error
      }
    }

    if (
      specific !== undefined ||
      Object.values(address.inputs ?? {}).some((input) => input !== undefined) ||
      store !== params.store
    )
      return doOpen(address, store, generation, specific)

    const flightID = JSON.stringify([cacheID(address), address.atVersion])

    while (inFlight.has(flightID)) await inFlight.get(flightID)

    const run = doOpen(address, store, generation)
    const gate = run.then(
      () => {},
      () => {},
    )

    inFlight.set(flightID, gate)
    try {
      return await run
    } finally {
      if (inFlight.get(flightID) === gate) inFlight.delete(flightID)
    }
  }

  async function decrypt(
    row: EntryRow | undefined,
    address: OpenKeyParams,
    store = params.store,
    specific = false,
  ): Promise<Uint8Array> {
    if (row === undefined) throw new VaultNotFound()

    const opened = await open(
      { ...address, atVersion: row.keyVersion },
      store,
      specific ? row.provenance : undefined,
    )

    try {
      if (params.mode === 'replicated' && row.provenance !== opened.branchID)
        throw new VaultSupersededBranch()

      return getSuite(opened.suite).decryptEntry({ ...row, contentKey: opened.contentKey })
    } finally {
      opened.contentKey.fill(0)
    }
  }

  return { open, decrypt, revoked }
}
