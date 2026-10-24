import type {
  RecordAuthorizeContext,
  RecordClaim,
  RecordDependency,
  RecordKey,
  RecordLockKey,
  RecordStoreAdapter,
  RecordTypeDefinition,
  SignedRecord,
  VerifiedRecordOp,
  VisibilityContext,
} from '@kokuin/records'
import {
  compareRecordDecisionHLC,
  parseCanonicalHLC,
  RecordContentRefusalError,
  recordPayloadDigest,
  recordPayloadMatches,
  verifyRecordOp,
  verifySignedRecord,
} from '@kokuin/records'
import type { MethodRegistry } from '@kokuin/token'
import { normalizeDID } from '@kokuin/token'

import type { FactorDescriptor } from './factors.js'
import type { DecodedVaultRecord, VaultRecordType } from './records.js'
import {
  decodeVaultRecord,
  encodeVaultRecordPayload,
  VAULT_RECORD_TYPES,
  vaultRecordMeta,
} from './records.js'

export type CredentialRecordReadPort = Pick<RecordStoreAdapter, 'get' | 'getMany' | 'list'>

export type CredentialAuthorityRequest = {
  source: 'record'
  op: VerifiedRecordOp
  owner: string
  issuer: string
  verb: 'read' | 'administer'
  recordKey: RecordKey
  transportContext: unknown
  record: SignedRecord
  store: CredentialRecordReadPort
}

export type CredentialAuthority = {
  authorize(request: CredentialAuthorityRequest): Promise<boolean>
}

export type VaultKeyAddress = { ownerDID: string; keyID: string }

export type VaultRecordPorts = {
  retainEntryCandidate(record: SignedRecord): Promise<void>
  listRevocations(address: VaultKeyAddress): Promise<Array<string>>
  dropRevokedWrappings(address: VaultKeyAddress): Promise<void>
}

export type VaultRecordHooks = {
  authority: CredentialAuthority
  validateConsumerMetadata(value: unknown, request: CredentialAuthorityRequest): Promise<boolean>
  /** Must resolve ports bound to this adapter's transaction, including routed adapters. */
  portsFor(store: RecordStoreAdapter): VaultRecordPorts
}

export type VaultRecordTypeParams = VaultRecordHooks & { opKind: string; methods?: MethodRegistry }

const KEY = 'vault.key'
const BRANCH = 'vault.key-branch'
const WRAPPING = 'vault.wrapping'
const ENTRY = 'vault.entry'
const REVOCATION = 'vault.revocation'

function requestFor(
  op: VerifiedRecordOp,
  record: SignedRecord,
  store: RecordStoreAdapter,
  transportContext: unknown,
  verb: 'read' | 'administer',
): CredentialAuthorityRequest {
  const getMany = store.getMany
  const read: CredentialRecordReadPort = {
    get: (key) => store.get(key),
    list: (types) => store.list(types),
    ...(getMany === undefined
      ? {}
      : { getMany: (keys: ReadonlyArray<RecordKey>) => getMany.call(store, keys) }),
  }

  return {
    source: 'record',
    op,
    owner: op.claim.owner,
    issuer: op.issuer,
    verb,
    recordKey: { type: op.claim.type, owner: op.claim.owner, id: op.claim.id },
    transportContext,
    record,
    store: read,
  }
}

async function authorized(
  params: VaultRecordTypeParams,
  request: CredentialAuthorityRequest,
): Promise<boolean> {
  return (
    (await params.validateConsumerMetadata(request.op.claim.meta.consumer, request)) &&
    (await params.authority.authorize(request))
  )
}

function entryOrder(claim: RecordClaim): ReadonlyArray<number> {
  const meta = vaultRecordMeta(ENTRY, claim)
  const stamp = meta === null ? null : parseCanonicalHLC(meta.contentHLC)

  if (meta === null || stamp === null)
    throw new RecordContentRefusalError('Entry content stamp is malformed')

  const node = Array.from({ length: stamp.nodeID.length }, (_, i) => stamp.nodeID.charCodeAt(i))

  return [stamp.wallTime, stamp.counter, ...node, -1, meta.keyVersion]
}

function keyOrder(claim: RecordClaim): ReadonlyArray<number> {
  const meta = vaultRecordMeta(KEY, claim)

  if (meta === null) throw new RecordContentRefusalError('Key metadata is malformed')

  return [meta.version, claim.deleted ? 2 : meta.state === 'retired' ? 1 : 0]
}

function validStructure(type: VaultRecordType, op: VerifiedRecordOp): boolean {
  const meta = vaultRecordMeta(type, op.claim)

  if (meta === null) return false

  if (type === ENTRY) {
    const entry = vaultRecordMeta(ENTRY, op.claim)

    return (
      entry !== null &&
      parseCanonicalHLC(op.claim.hlc) !== null &&
      compareRecordDecisionHLC(entry.contentHLC, op.claim.hlc) <= 0
    )
  }

  return true
}

function decodedAs<Type extends VaultRecordType>(
  record: SignedRecord,
  op: VerifiedRecordOp,
  type: Type,
): Extract<DecodedVaultRecord, { type: Type }> | null {
  if (op.claim.deleted || !recordPayloadMatches(record, op.claim)) return null

  try {
    const decoded = decodeVaultRecord(record, op.claim.meta)

    return decoded.type === type ? (decoded as Extract<DecodedVaultRecord, { type: Type }>) : null
  } catch {
    return null
  }
}

function keyAtLeast(owner: string, keyID: string, version: number): RecordDependency {
  return {
    type: KEY,
    owner,
    id: keyID,
    satisfiedBy: (op) => {
      const meta = vaultRecordMeta(KEY, op.claim)

      return op.claim.owner === owner && meta !== null && meta.version >= version
    },
  }
}

function exactBranch(
  op: VerifiedRecordOp,
  meta: { keyID: string; keyVersion: number; branchID: string; branchRecordID: string },
): RecordDependency {
  return {
    type: BRANCH,
    owner: op.claim.owner,
    id: meta.branchRecordID,
    satisfiedBy: (branch) => {
      const info = vaultRecordMeta(BRANCH, branch.claim)

      return (
        info !== null &&
        branch.claim.owner === op.claim.owner &&
        !branch.claim.deleted &&
        info.keyID === meta.keyID &&
        info.keyVersion === meta.keyVersion &&
        info.branchID === meta.branchID
      )
    },
  }
}

function dependencies(
  type: VaultRecordType,
  op: VerifiedRecordOp,
): ReadonlyArray<RecordDependency> {
  if (type === KEY) return []

  const meta = vaultRecordMeta(type, op.claim)

  if (meta === null) return []

  const key = { type: KEY, owner: op.claim.owner, id: meta.keyID }

  if (type === REVOCATION) return [key]

  const version = op.claim.meta.keyVersion as number

  if (type === BRANCH) return [keyAtLeast(op.claim.owner, meta.keyID, version)]

  const result: Array<RecordDependency> = [
    type === WRAPPING && op.claim.deleted ? key : keyAtLeast(op.claim.owner, meta.keyID, version),
  ]

  if (type === WRAPPING && op.claim.deleted) return result

  const { branchID, branchRecordID } = op.claim.meta

  if (typeof branchID === 'string' && typeof branchRecordID === 'string')
    result.push(
      exactBranch(op, { keyID: meta.keyID, keyVersion: version, branchID, branchRecordID }),
    )

  return result
}

async function keyOwnerMatches(
  params: VaultRecordTypeParams,
  op: VerifiedRecordOp,
  ctx: RecordAuthorizeContext,
): Promise<boolean> {
  // Apply serves the chunk's batched view. Holder proofs outside apply read the store.
  const read = ctx.decision ?? ((key: RecordKey) => ctx.store.get(key))
  const decision = await read({
    type: KEY,
    owner: op.claim.owner,
    id: op.claim.meta.keyID as string,
  })

  if (decision === null) return false

  for (const record of decision.copies) {
    const key = await verifySignedRecord(record, params.opKind, params.methods)

    if (
      key !== null &&
      vaultRecordMeta(KEY, key.claim) !== null &&
      key.claim.owner === op.claim.owner
    )
      return true
  }

  return false
}

async function revoked(
  params: VaultRecordTypeParams,
  op: VerifiedRecordOp,
  store: RecordStoreAdapter,
  descriptors: Array<FactorDescriptor>,
): Promise<boolean> {
  const denied = new Set(
    (
      await params
        .portsFor(store)
        .listRevocations({ ownerDID: op.claim.owner, keyID: op.claim.meta.keyID as string })
    ).map((did) => normalizeDID(did)),
  )
  const recipients = [
    op.claim.meta.recipient,
    ...descriptors.filter((d) => d.kind === 'did').map((d) => d.params.recipient),
  ]

  for (const recipient of recipients) {
    if (recipient === null || recipient === undefined) continue

    if (typeof recipient !== 'string') return true

    try {
      if (denied.has(normalizeDID(recipient))) return true
    } catch {
      return true
    }
  }

  return false
}

async function authorizeBranch(
  params: VaultRecordTypeParams,
  op: VerifiedRecordOp,
  ctx: RecordAuthorizeContext,
): Promise<boolean> {
  const meta = vaultRecordMeta(BRANCH, op.claim)
  const decoded = decodedAs(ctx.record, op, BRANCH)

  if (meta === null || decoded === null) return false

  const payload = decoded.payload
  const introducing = await verifyRecordOp(payload.opJWT, params.opKind, params.methods)
  const key = introducing === null ? null : vaultRecordMeta(KEY, introducing.claim)

  if (
    introducing === null ||
    key === null ||
    introducing.claim.deleted ||
    introducing.claim.id !== meta.keyID ||
    introducing.claim.owner !== op.claim.owner ||
    key.version !== meta.keyVersion ||
    introducing.opHash !== payload.opHash ||
    introducing.claim.hlc !== payload.hlc ||
    introducing.issuer !== normalizeDID(payload.authorDID) ||
    meta.branchID !== `${payload.hlc}:${payload.opHash}`
  )
    return false

  const keyPayload = encodeVaultRecordPayload(KEY, {
    suite: payload.suite,
    state: key.state as 'active' | 'retired',
  })

  if (introducing.claim.payloadDigest !== recordPayloadDigest(keyPayload)) return false

  // The embedded op is independent authenticated evidence and gets its own consumer decision.
  const keyRecord: SignedRecord = {
    type: KEY,
    id: introducing.claim.id,
    owner: introducing.claim.owner,
    hlc: introducing.claim.hlc,
    payload: keyPayload,
    opJWT: payload.opJWT,
    opHash: introducing.opHash,
  }

  return (
    (await authorized(
      params,
      requestFor(introducing, keyRecord, ctx.store, ctx.transportContext, 'administer'),
    )) &&
    (await authorized(
      params,
      requestFor(op, ctx.record, ctx.store, ctx.transportContext, 'administer'),
    ))
  )
}

function createType(
  type: VaultRecordType,
  params: VaultRecordTypeParams,
  bindReceiver = true,
): RecordTypeDefinition {
  const definition: RecordTypeDefinition = {
    type,
    policy:
      type === KEY
        ? { kind: 'monotonic', version: keyOrder }
        : type === ENTRY
          ? { kind: 'monotonic', version: entryOrder }
          : type === BRANCH
            ? { kind: 'immutable' }
            : { kind: 'lww' },
    dependsOn: type === KEY ? [] : type === ENTRY || type === WRAPPING ? [KEY, BRANCH] : [KEY],
    precheck: async (op) => validStructure(type, op),
    dependencies: (_record, op) => dependencies(type, op),
    async authorize(op, ctx) {
      // Enforce the factory's replay domain even when the engine is misconfigured.
      const checked = await verifySignedRecord(ctx.record, params.opKind, params.methods)

      if (checked === null || checked.opHash !== op.opHash) return false

      if (!validStructure(type, op) || !recordPayloadMatches(ctx.record, op.claim)) return false

      if (type !== KEY && !(await keyOwnerMatches(params, op, ctx))) return false

      if (type === BRANCH) return await authorizeBranch(params, op, ctx)

      if (!op.claim.deleted) {
        const decoded = decodedAs(ctx.record, op, type)

        if (decoded === null) return false

        if (decoded.type === KEY && decoded.payload.state !== op.claim.meta.state) return false

        if (
          decoded.type === WRAPPING &&
          (await revoked(params, op, ctx.store, decoded.payload.descriptors))
        )
          return false
      }

      if (
        !(await authorized(
          params,
          requestFor(op, ctx.record, ctx.store, ctx.transportContext, 'administer'),
        ))
      )
        return false

      return (
        type !== WRAPPING ||
        !bindReceiver ||
        (await authorized(
          params,
          requestFor(op, ctx.record, ctx.store, ctx.transportContext, 'read'),
        ))
      )
    },
    async visibleTo(record, ctx) {
      if (ctx.opKind !== params.opKind) return false

      const op = await verifySignedRecord(record, params.opKind, params.methods)

      if (op === null || !validStructure(type, op) || !recordPayloadMatches(record, op.claim))
        return false

      if (!op.claim.deleted) {
        const decoded = decodedAs(record, op, type)

        if (decoded === null) return false

        if (
          decoded.type === WRAPPING &&
          (await revoked(params, op, ctx.store, decoded.payload.descriptors))
        )
          return false
      }

      return await authorized(
        params,
        requestFor(op, record, ctx.store, ctx.transportContext, 'read'),
      )
    },
    async lockKeys(incoming, stored) {
      const keys = new Map<string, RecordLockKey>()
      const records = [incoming, ...(stored?.copies ?? [])]
      const ops = await Promise.all(
        records.map((record) => verifySignedRecord(record, params.opKind, params.methods)),
      )

      for (const op of ops) {
        if (op === null) continue

        const keyID = op.claim.type === KEY ? op.claim.id : op.claim.meta.keyID

        if (typeof keyID !== 'string' || keyID === '') continue

        const key = JSON.stringify([op.claim.owner, keyID])

        keys.set(key, { type: KEY, key })
      }

      return [...keys.values()]
    },
  }

  if (type === KEY) {
    // Equal-version branches remain independently proven; the current head uses claim digest.
    definition.onEqual = () => 'fork'
  }

  if (type === ENTRY) {
    definition.afterAuthorize = async (record, store) => {
      await params.portsFor(store).retainEntryCandidate(record)
    }
  }

  if (type === WRAPPING || type === REVOCATION) {
    definition.afterApply = async (record, store) => {
      const op = await verifySignedRecord(record, params.opKind, params.methods)

      if (op === null) throw new Error('Applied record signature is invalid')

      await params
        .portsFor(store)
        .dropRevokedWrappings({ ownerDID: op.claim.owner, keyID: op.claim.meta.keyID as string })
    }
  }

  return definition
}

/** One explicit replay domain and consumer policy for the five generic record types. */
export function vaultRecordTypes(params: VaultRecordTypeParams): Map<string, RecordTypeDefinition> {
  if (typeof params.opKind !== 'string' || params.opKind.length === 0)
    throw new TypeError('An explicit operation kind is required')

  return new Map(VAULT_RECORD_TYPES.map((type) => [type, createType(type, params)]))
}

/** Only wrappings can prove key holding, regardless of other records' metadata. */
export function vaultHolderTypes(
  types: ReadonlyMap<string, RecordTypeDefinition>,
): ReadonlyMap<string, RecordTypeDefinition> {
  const wrapping = types.get(WRAPPING)

  return new Map(wrapping === undefined ? [] : [[WRAPPING, wrapping]])
}

/** Read a live, owner-qualified key version in the explicit replay domain. */
export function vaultKeyVersionReader(
  store: RecordStoreAdapter,
  params: Pick<VaultRecordTypeParams, 'opKind' | 'methods'>,
): VisibilityContext['currentKeyVersion'] {
  return async (owner, keyID) => {
    const stored = await store.get({ type: KEY, owner, id: keyID })
    const copy = stored?.copies[0]
    const op =
      copy === undefined ? null : await verifySignedRecord(copy, params.opKind, params.methods)
    const meta = op === null ? null : vaultRecordMeta(KEY, op.claim)

    return op === null || meta === null || op.claim.deleted || op.claim.owner !== owner
      ? null
      : meta.version
  }
}

/** Proofs retain consumer authority checks but are never addressed to the local receiver. */
export function vaultProofAuthorizer(
  params: VaultRecordTypeParams,
  store: RecordStoreAdapter,
  transportContext?: unknown,
): VisibilityContext['authorizeProof'] {
  const wrapping = createType(WRAPPING, params, false)

  return async (record, stored) => {
    if (record.type !== WRAPPING) return false

    const op = await verifySignedRecord(record, params.opKind, params.methods)

    if (op === null) return false

    return await wrapping.authorize(op, {
      record,
      stored,
      store,
      transportContext,
      // Generic vault policy delegates all authority to the consumer callback.
      resolveController: async () => null,
      verifyCapability: async () => false,
    })
  }
}
