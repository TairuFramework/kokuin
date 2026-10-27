import { withKeyLocks, withStoreTransaction } from '@hozon/db'
import type { RecordDecision, RecordKey, SignedRecord, VerifiedRecordOp } from '@kokuin/records'
import {
  getRecordDecisions,
  recordClaimDigest,
  recordKeyText,
  recordPayloadDigest,
  signRecordOp,
  verifySignedRecord,
} from '@kokuin/records'
import type {
  KeyCache,
  VaultRecordMetas,
  VaultRecordPayloads,
  VaultRecordType,
} from '@kokuin/vault'
import {
  checkDescriptorDigest,
  createKeyCache,
  decodeVaultRecord,
  encodeVaultRecordPayload,
  selectWinningBranch,
  VaultTampered,
} from '@kokuin/vault'

import type {
  CoordinatorCall,
  UnverifiableWrapping,
  VaultCoordinatorParams,
} from './coordinator-types.js'
import { getVaultStore } from './definition.js'
import { VaultWriteConflict, vaultDatabases } from './record-context.js'
import type { VaultKeyBranch, VaultRecords, VaultWritePreconditions } from './records.js'
import { createVaultRecords, VaultRecordRowError } from './records.js'
import { settleAll, settledValue } from './settle.js'
import type { KeyAddress, KeyRow, VaultStoreAPI, WrappingRow } from './types.js'

export class VaultNotAuthorized extends Error {
  constructor(verb: 'read' | 'administer') {
    super(`Vault ${verb} authority refused the operation`)
    this.name = 'VaultNotAuthorized'
  }
}

export class VaultNotFound extends Error {
  constructor() {
    super('Vault key, entry or authenticated evidence not found')
    this.name = 'VaultNotFound'
  }
}

export class VaultSecretUnverifiable extends Error {
  #wrapping: UnverifiableWrapping

  constructor(wrapping: UnverifiableWrapping) {
    super('Retained foreign DID wrapping requires explicit trust and supplied secret inputs')
    this.name = 'VaultSecretUnverifiable'
    this.#wrapping = { ...wrapping, factorKinds: [...wrapping.factorKinds] }
  }

  get wrappingID(): string {
    return this.#wrapping.wrappingID
  }

  get recipientDID(): string {
    return this.#wrapping.recipientDID
  }

  get factorKinds(): Array<string> {
    return [...this.#wrapping.factorKinds]
  }
}

export class VaultRepairPending extends Error {
  constructor() {
    super('Vault branch material is unavailable for repair')
    this.name = 'VaultRepairPending'
  }
}

export class VaultSupersededBranch extends Error {
  constructor() {
    super('Entry belongs to a superseded content-key branch')
    this.name = 'VaultSupersededBranch'
  }
}

export class VaultKeyLocked extends Error {
  constructor() {
    super('Vault key requires supplied factors')
    this.name = 'VaultKeyLocked'
  }
}

export type StoredRecordEvidence = {
  record: SignedRecord
  op: VerifiedRecordOp
}

export type WrappingEvidence = StoredRecordEvidence & { expectedDescriptorDigest: string }

export type KeyBranch = {
  branchID: string
  branchRecordID: string
  suite: number
}

export type KeyRecords = {
  records: Array<SignedRecord>
  branchID: string
  branchRecordID: string
}

export type CoordinatorContext = {
  params: VaultCoordinatorParams
  cache: KeyCache
  cacheID(address: KeyAddress): string
  records: VaultRecords | undefined
  recordsFor(store: VaultStoreAPI): VaultRecords
  authorize(
    operation: string,
    verb: 'read' | 'administer',
    address: { ownerDID: string; keyID?: string; entryID?: string } & CoordinatorCall,
    store?: VaultStoreAPI,
  ): Promise<void>
  key(address: KeyAddress, store?: VaultStoreAPI): Promise<KeyRow>
  signed<Type extends VaultRecordType>(
    type: Type,
    address: { ownerDID: string; id: string },
    payload: VaultRecordPayloads[Type] | null,
    meta: VaultRecordMetas[Type],
    hlc?: string,
  ): Promise<SignedRecord>
  verified(record: SignedRecord): Promise<VerifiedRecordOp>
  stored(address: RecordKey, store?: VaultStoreAPI): Promise<StoredRecordEvidence>
  /** One batched read. Throws the first missing or unverifiable record in address order. */
  storedMany(
    addresses: ReadonlyArray<RecordKey>,
    store?: VaultStoreAPI,
  ): Promise<Array<StoredRecordEvidence>>
  wrappingEvidence(row: WrappingRow, store?: VaultStoreAPI): Promise<WrappingEvidence | undefined>
  /** Replicated evidence for each row, in row order, from one batched read. Empty in local mode. */
  wrappingEvidences(
    rows: ReadonlyArray<WrappingRow>,
    store?: VaultStoreAPI,
  ): Promise<Array<WrappingEvidence>>
  branches(
    address: KeyAddress,
    version: number,
    store?: VaultStoreAPI,
  ): Promise<Array<VaultKeyBranch>>
  branch(
    address: KeyAddress,
    version: number,
    store?: VaultStoreAPI,
    specific?: string,
  ): Promise<KeyBranch>
  write(
    store: VaultStoreAPI,
    output: Array<SignedRecord>,
    preconditions: VaultWritePreconditions,
    call: CoordinatorCall,
  ): Promise<void>
  keyRecords(
    row: KeyRow,
    store: VaultStoreAPI,
    unique?: string,
    consumer?: unknown,
  ): Promise<KeyRecords>
  locked<Result>(
    addresses: ReadonlyArray<KeyAddress>,
    fn: (store: VaultStoreAPI) => Promise<Result>,
  ): Promise<Result>
  read<Result>(fn: (store: VaultStoreAPI) => Promise<Result>): Promise<Result>
  evict(address: KeyAddress): void
  evictAll(ownerDID: string): void
  generation(address: KeyAddress): string
}

export function createCoordinatorContext(params: VaultCoordinatorParams): CoordinatorContext {
  if (params.authority === undefined) throw new TypeError('CredentialAuthority is required')

  const cache = createKeyCache(params.cache)
  const generations = new Map<string, { ownerDID: string; value: number }>()
  const cacheID = (address: KeyAddress) => JSON.stringify([address.ownerDID, address.keyID])
  // One records object per store handle. It holds no per-call state: its adapter reads through the
  // handle's own database, and lock state lives only on adapters built inside `transaction`.
  const recordsByStore = new WeakMap<VaultStoreAPI, VaultRecords>()
  const recordsFor = (store: VaultStoreAPI): VaultRecords => {
    if (params.mode !== 'replicated') throw new TypeError('Local coordinator has no records path')

    let records = recordsByStore.get(store)

    if (records === undefined) {
      records = createVaultRecords({ ...params.records, store, authority: params.authority })
      recordsByStore.set(store, records)
    }

    return records
  }
  const records = params.mode === 'replicated' ? recordsFor(params.store) : undefined

  async function authorize(
    operation: string,
    verb: 'read' | 'administer',
    address: { ownerDID: string; keyID?: string; entryID?: string } & CoordinatorCall,
    store = params.store,
  ) {
    const allowed = await params.authority.authorize({
      source: 'local',
      mode: params.mode,
      operation,
      verb,
      owner: address.ownerDID,
      issuer: params.principal,
      keyID: address.keyID,
      entryID: address.entryID,
      transportContext: address.transportContext,
      request: address,
      store: {
        getKey: (a) => store.getKey(a),
        getEntry: (a) => store.getEntry(a),
        listKeys: (a) => store.listKeys(a),
        listWrappings: (a) => store.listWrappings(a),
        listEntries: (a) => store.listEntries(a),
      },
    })

    if (!allowed) throw new VaultNotAuthorized(verb)
  }

  async function key(address: KeyAddress, store = params.store): Promise<KeyRow> {
    const row = await store.getKey(address)

    if (row === undefined) throw new VaultNotFound()

    return row
  }

  async function signed<Type extends VaultRecordType>(
    type: Type,
    address: { ownerDID: string; id: string },
    payload: VaultRecordPayloads[Type] | null,
    meta: VaultRecordMetas[Type],
    hlc?: string,
  ): Promise<SignedRecord> {
    if (params.mode !== 'replicated') throw new TypeError('Local writes are unsigned')

    const bytes = payload === null ? null : encodeVaultRecordPayload(type, payload)
    const stamp = hlc ?? (await params.nextHLC())
    const claim = {
      type,
      id: address.id,
      owner: address.ownerDID,
      hlc: stamp,
      payloadDigest: recordPayloadDigest(bytes),
      deleted: bytes === null,
      meta,
    }

    return {
      type,
      id: address.id,
      owner: address.ownerDID,
      hlc: stamp,
      payload: bytes,
      ...(await signRecordOp(params.signer, claim, params.records.opKind)),
    }
  }

  async function verified(record: SignedRecord): Promise<VerifiedRecordOp> {
    if (params.mode !== 'replicated') throw new TypeError('Local rows have no signed evidence')

    const op = await verifySignedRecord(record, params.records.opKind, params.records.methods)

    if (op === null) throw new VaultNotFound()

    return op
  }

  async function stored(address: RecordKey, store = params.store): Promise<StoredRecordEvidence> {
    const record = (await recordsFor(store).adapter.get(address))?.copies[0]

    if (record === undefined) throw new VaultNotFound()

    return { record, op: await verified(record) }
  }

  async function storedMany(
    addresses: ReadonlyArray<RecordKey>,
    store = params.store,
  ): Promise<Array<StoredRecordEvidence>> {
    const decisions = await getRecordDecisions(recordsFor(store).adapter, addresses)

    return settleAll(
      addresses.map(async (address) => {
        const record = decisions.get(recordKeyText(address))?.copies[0]

        if (record === undefined) throw new VaultNotFound()

        return { record, op: await verified(record) }
      }),
    )
  }

  function checkWrapping(row: WrappingRow, evidence: StoredRecordEvidence): WrappingEvidence {
    const decoded = decodeVaultRecord(evidence.record, evidence.op.claim.meta)

    if (
      decoded.type !== 'vault.wrapping' ||
      decoded.meta.keyID !== row.keyID ||
      decoded.meta.keyVersion !== row.keyVersion ||
      decoded.meta.branchID !== row.provenance ||
      decoded.meta.recipient !== row.recipientDID
    )
      throw new VaultTampered('Wrapping projection disagrees with authenticated metadata')

    checkDescriptorDigest({
      descriptors: row.descriptors,
      expectedDescriptorDigest: decoded.payload.descriptorDigest,
    })

    const equal = (a: Uint8Array, b: Uint8Array) => {
      return a.length === b.length && a.every((v, i) => v === b[i])
    }

    if (!equal(row.iv, decoded.payload.iv) || !equal(row.wrappedKey, decoded.payload.wrappedKey))
      throw new VaultTampered('Wrapping projection disagrees with authenticated ciphertext')

    return { ...evidence, expectedDescriptorDigest: decoded.payload.descriptorDigest }
  }

  async function wrappingEvidences(
    rows: ReadonlyArray<WrappingRow>,
    store = params.store,
  ): Promise<Array<WrappingEvidence>> {
    if (params.mode === 'local') return []

    const evidence = await storedMany(
      rows.map((row) => ({ type: 'vault.wrapping', owner: row.ownerDID, id: row.wrappingID })),
      store,
    )

    return rows.map((row, index) => {
      const item = evidence[index]

      if (item === undefined) throw new VaultNotFound()

      return checkWrapping(row, item)
    })
  }

  async function wrappingEvidence(
    row: WrappingRow,
    store = params.store,
  ): Promise<WrappingEvidence | undefined> {
    if (params.mode === 'local') return undefined

    const evidence = await stored(
      { type: 'vault.wrapping', owner: row.ownerDID, id: row.wrappingID },
      store,
    )

    return checkWrapping(row, evidence)
  }

  async function branches(
    address: KeyAddress,
    version: number,
    store = params.store,
  ): Promise<Array<VaultKeyBranch>> {
    return params.mode === 'local'
      ? []
      : recordsFor(store).listKeyBranches({ ...address, keyVersion: version })
  }

  async function branch(
    address: KeyAddress,
    version: number,
    store = params.store,
    specific?: string,
  ): Promise<KeyBranch> {
    if (params.mode === 'local')
      return { branchID: '', branchRecordID: '', suite: (await key(address, store)).suite }

    const rows = await branches(address, version, store)

    if (rows.length === 0) throw new VaultRepairPending()

    const winner = selectWinningBranch(rows.map((row) => row.introducingOp))
    const branchID = specific ?? `${winner.claim.hlc}:${winner.opHash}`
    const proofs = rows
      .filter((row) => row.branchID === branchID)
      .map((row) => row.branchRecordID)
      .sort()

    if (proofs.length === 0) throw new VaultRepairPending()

    const adapter = recordsFor(store).adapter
    // A projection row that names no matching record is local corruption. `repairFork` rebuilds it.
    const corrupt = (id: string, reason: string): void => {
      params.records.onCorruptRow?.({ type: 'vault.key-branch', id, error: new Error(reason) })
    }

    const keys = proofs.map((id) => ({ type: 'vault.key-branch', owner: address.ownerDID, id }))
    // One batched read. A corrupt row fails the whole batch, so then each proof is read alone and
    // only the corrupt one is reported.
    const read = async (): Promise<Array<RecordDecision | null | VaultRecordRowError>> => {
      try {
        const decisions = await getRecordDecisions(adapter, keys)

        return keys.map((key) => decisions.get(recordKeyText(key)) ?? null)
      } catch (error) {
        if (!(error instanceof VaultRecordRowError)) throw error
      }

      const each: Array<RecordDecision | null | VaultRecordRowError> = []

      for (const key of keys) {
        try {
          each.push(await adapter.get(key))
        } catch (error) {
          if (!(error instanceof VaultRecordRowError)) throw error

          each.push(error)
        }
      }

      return each
    }
    const decisions = await read()
    // Verify every proof together, then consume the results in proof order, as a sequential
    // scan would: the first failure reached is the one thrown.
    const checks = await Promise.allSettled(
      decisions.map((decision) => {
        const record = decision instanceof VaultRecordRowError ? undefined : decision?.copies[0]

        return record === undefined ? Promise.resolve(null) : verified(record)
      }),
    )

    // Read only the projected proof records. Any mismatch fails closed, as a full scan would.
    for (const [index, id] of proofs.entries()) {
      const decision = decisions[index] ?? null

      if (decision instanceof VaultRecordRowError) {
        params.records.onCorruptRow?.({ type: 'vault.key-branch', id, error: decision })
        continue
      }

      const record = decision?.copies[0]

      if (record === undefined) {
        corrupt(id, 'Key-branch projection names a missing record')
        continue
      }

      // A present record was checked by `verified`, which throws rather than yield null.
      const op = settledValue(checks[index] as PromiseSettledResult<VerifiedRecordOp>)

      if (
        op.claim.meta.keyID !== address.keyID ||
        op.claim.meta.keyVersion !== version ||
        op.claim.meta.branchID !== branchID
      ) {
        corrupt(id, 'Key-branch projection disagrees with its signed record')
        continue
      }

      const decoded = decodeVaultRecord(record, op.claim.meta)

      if (decoded.type === 'vault.key-branch')
        return { branchID, branchRecordID: record.id, suite: decoded.payload.suite }

      corrupt(id, 'Key-branch projection names a record of another type')
    }

    throw new VaultRepairPending()
  }

  async function write(
    store: VaultStoreAPI,
    output: Array<SignedRecord>,
    preconditions: VaultWritePreconditions,
    call: CoordinatorCall,
  ) {
    const result = await recordsFor(store).write({
      records: output,
      preconditions,
      transportContext: call.transportContext,
    })

    if (result.rejected.length > 0 || result.parked.length > 0) throw new VaultWriteConflict()

    const decisions = await getRecordDecisions(recordsFor(store).adapter, output)

    await settleAll(
      output.map(async (record) => {
        const selected = decisions.get(recordKeyText(record))?.copies[0]

        if (selected === undefined) throw new VaultWriteConflict()

        const [selectedOp, expectedOp] = await settleAll([verified(selected), verified(record)])

        if (recordClaimDigest(selectedOp.claim) !== recordClaimDigest(expectedOp.claim))
          throw new VaultWriteConflict()
      }),
    )
  }

  async function keyRecords(
    row: KeyRow,
    store: VaultStoreAPI,
    unique?: string,
    consumer?: unknown,
  ): Promise<KeyRecords> {
    const previous =
      unique === undefined
        ? await stored({ type: 'vault.key', owner: row.ownerDID, id: row.keyID }, store)
        : undefined
    const keyUnique = unique ?? previous?.op.claim.meta.keyUnique

    if (typeof keyUnique !== 'string') throw new VaultNotFound()

    const record = await signed(
      'vault.key',
      { ownerDID: row.ownerDID, id: row.keyID },
      { suite: row.suite, state: row.state },
      {
        keyID: row.keyID,
        keyUnique,
        version: row.version,
        state: row.state,
        consumer: consumer === undefined ? (previous?.op.claim.meta.consumer ?? null) : consumer,
      },
    )
    const op = await verified(record)
    const branchID = `${record.hlc}:${record.opHash}`
    const payload = {
      authorDID: op.issuer,
      hlc: record.hlc,
      opJWT: record.opJWT,
      opHash: record.opHash,
      suite: row.suite,
    }
    const branchRecordID = recordPayloadDigest(
      encodeVaultRecordPayload('vault.key-branch', payload),
    )

    if (branchRecordID === null) throw new Error('Branch has no payload digest')

    const proof = await signed(
      'vault.key-branch',
      { ownerDID: row.ownerDID, id: branchRecordID },
      payload,
      {
        keyID: row.keyID,
        keyVersion: row.version,
        branchID,
        consumer: consumer === undefined ? (previous?.op.claim.meta.consumer ?? null) : consumer,
      },
      record.hlc,
    )

    return { records: [record, proof], branchID, branchRecordID }
  }

  async function locked<Result>(
    addresses: ReadonlyArray<KeyAddress>,
    fn: (store: VaultStoreAPI) => Promise<Result>,
  ): Promise<Result> {
    const database = vaultDatabases.get(params.store)

    if (database === undefined) throw new TypeError('Coordinator requires a registered vault store')

    return withKeyLocks(
      database.context.provider,
      'vault_keys',
      addresses.map((a) => [JSON.stringify([a.ownerDID, a.keyID])]),
      async (provider) => {
        const store = await getVaultStore(provider)
        const transaction = vaultDatabases.get(store)

        if (transaction === undefined)
          throw new TypeError('Transaction-bound vault store is unavailable')

        return withStoreTransaction(transaction.db, () => fn(store))
      },
    )
  }

  async function read<Result>(fn: (store: VaultStoreAPI) => Promise<Result>): Promise<Result> {
    const database = vaultDatabases.get(params.store)

    if (database === undefined) throw new TypeError('Coordinator requires a registered vault store')

    return database.context.provider.withTransaction(async (provider) => {
      const store = await getVaultStore(provider)
      const transaction = vaultDatabases.get(store)

      if (transaction === undefined)
        throw new TypeError('Transaction-bound vault store is unavailable')

      return withStoreTransaction(transaction.db, () => fn(store))
    })
  }

  function evict(address: KeyAddress) {
    const id = cacheID(address)

    generations.set(id, {
      ownerDID: address.ownerDID,
      value: (generations.get(id)?.value ?? 0) + 1,
    })

    cache.evict(id)
  }

  function evictAll(ownerDID: string) {
    for (const [id, generation] of generations) {
      if (generation.ownerDID !== ownerDID) continue

      generation.value += 1
      cache.evict(id)
    }
  }

  function generation(address: KeyAddress) {
    const id = cacheID(address)
    let current = generations.get(id)

    if (current === undefined) {
      current = { ownerDID: address.ownerDID, value: 0 }
      generations.set(id, current)
    }

    return String(current.value)
  }

  return {
    params,
    cache,
    cacheID,
    records,
    recordsFor,
    authorize,
    key,
    signed,
    verified,
    stored,
    storedMany,
    wrappingEvidence,
    wrappingEvidences,
    branches,
    branch,
    write,
    keyRecords,
    locked,
    read,
    evict,
    evictAll,
    generation,
  }
}
