import { nobleCrypto } from '@kokuin/crypto'
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
import type { CryptoOptions, MethodRegistry } from '@kokuin/token'
import { normalizeDID } from '@kokuin/token'

import type { FactorDescriptor } from './factors.js'
import type { DecodedVaultRecord, VaultRecordMetas, VaultRecordType } from './records.js'
import {
  decodeVaultRecord,
  encodeVaultRecordPayload,
  parseVaultRecordMeta,
  VAULT_RECORD_TYPES,
  VaultRecordPayloadError,
  vaultRecordMeta,
} from './records.js'

type RequestForParams = {
  op: VerifiedRecordOp
  record: SignedRecord
  store: RecordStoreAdapter
  transportContext: unknown
  verb: 'read' | 'administer'
}
type DecodedAsParams<Type extends VaultRecordType> = {
  record: SignedRecord
  op: VerifiedRecordOp
  type: Type
  options: CryptoOptions
}
type RevokedParams = {
  params: VaultRecordTypeParams
  op: VerifiedRecordOp
  store: RecordStoreAdapter
  descriptors: Array<FactorDescriptor>
}

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

export type VaultRecordTypeParams = VaultRecordHooks &
  CryptoOptions & { opKind: string; methods?: MethodRegistry }

const KEY = 'vault.key'
const BRANCH = 'vault.key-branch'
const WRAPPING = 'vault.wrapping'
const ENTRY = 'vault.entry'
const REVOCATION = 'vault.revocation'

function requestFor({
  op,
  record,
  store,
  transportContext,
  verb,
}: RequestForParams): CredentialAuthorityRequest {
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
  const meta = parseVaultRecordMeta(ENTRY, claim)
  const stamp = meta === null ? null : parseCanonicalHLC(meta.contentHLC)

  if (meta === null || stamp === null)
    throw new RecordContentRefusalError({ message: 'Entry content stamp is malformed' })

  const node = Array.from({ length: stamp.nodeID.length }, (_, i) => stamp.nodeID.charCodeAt(i))

  return [stamp.wallTime, stamp.counter, ...node, -1, meta.keyVersion]
}

function keyOrder(claim: RecordClaim): ReadonlyArray<number> {
  const meta = parseVaultRecordMeta(KEY, claim)

  if (meta === null) throw new RecordContentRefusalError({ message: 'Key metadata is malformed' })

  return [meta.version, claim.deleted ? 2 : meta.state === 'retired' ? 1 : 0]
}

async function validStructure(
  type: VaultRecordType,
  op: VerifiedRecordOp,
  options: CryptoOptions,
): Promise<boolean> {
  const meta = await vaultRecordMeta(type, op.claim, options)

  if (meta === null) return false

  if (type === ENTRY) {
    const entry = meta as VaultRecordMetas['vault.entry']

    return (
      entry !== null &&
      parseCanonicalHLC(op.claim.hlc) !== null &&
      compareRecordDecisionHLC(entry.contentHLC, op.claim.hlc) <= 0
    )
  }

  return true
}

async function decodedAs<Type extends VaultRecordType>({
  record,
  op,
  type,
  options,
}: DecodedAsParams<Type>): Promise<Extract<DecodedVaultRecord, { type: Type }> | null> {
  if (op.claim.deleted || !(await recordPayloadMatches(record, op.claim, options))) return null

  try {
    const decoded = await decodeVaultRecord(record, op.claim.meta, options)

    return decoded.type === type ? (decoded as Extract<DecodedVaultRecord, { type: Type }>) : null
  } catch (error) {
    if (!(error instanceof VaultRecordPayloadError)) throw error
    return null
  }
}

function keyAtLeast(owner: string, keyID: string, version: number): RecordDependency {
  return {
    type: KEY,
    owner,
    id: keyID,
    satisfiedBy: (op) => {
      const meta = parseVaultRecordMeta(KEY, op.claim)

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
      const info = parseVaultRecordMeta(BRANCH, branch.claim)

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

  const meta = parseVaultRecordMeta(type, op.claim)

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

  const keys = await Promise.all(
    decision.copies.map((record) => {
      return verifySignedRecord({
        record: record,
        opKind: params.opKind,
        methods: params.methods,
        options: params,
      })
    }),
  )

  for (const key of keys) {
    if (
      key !== null &&
      key.claim.owner === op.claim.owner &&
      (await vaultRecordMeta(KEY, key.claim, params)) !== null
    )
      return true
  }
  return false
}

async function revoked({ params, op, store, descriptors }: RevokedParams): Promise<boolean> {
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
  const meta = await vaultRecordMeta(BRANCH, op.claim, params)
  const decoded = await decodedAs({ record: ctx.record, op: op, type: BRANCH, options: params })

  if (meta === null || decoded === null) return false

  const payload = decoded.payload
  const introducing = await verifyRecordOp({
    opJWT: payload.opJWT,
    opKind: params.opKind,
    methods: params.methods,
    options: params,
  })
  const key = introducing === null ? null : await vaultRecordMeta(KEY, introducing.claim, params)

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

  if (introducing.claim.payloadDigest !== (await recordPayloadDigest(keyPayload, params)))
    return false

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
      requestFor({
        op: introducing,
        record: keyRecord,
        store: ctx.store,
        transportContext: ctx.transportContext,
        verb: 'administer',
      }),
    )) &&
    (await authorized(
      params,
      requestFor({
        op: op,
        record: ctx.record,
        store: ctx.store,
        transportContext: ctx.transportContext,
        verb: 'administer',
      }),
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
    precheck: async (op) => await validStructure(type, op, params),
    dependencies: (_record, op) => dependencies(type, op),
    async authorize(op, ctx) {
      // Enforce the factory's replay domain even when the engine is misconfigured.
      const checked = await verifySignedRecord({
        record: ctx.record,
        opKind: params.opKind,
        methods: params.methods,
        options: params,
      })

      if (checked === null || checked.opHash !== op.opHash) return false

      if (
        !(await validStructure(type, op, params)) ||
        !(await recordPayloadMatches(ctx.record, op.claim, params))
      )
        return false

      if (type !== KEY && !(await keyOwnerMatches(params, op, ctx))) return false

      if (type === BRANCH) return await authorizeBranch(params, op, ctx)

      if (!op.claim.deleted) {
        const decoded = await decodedAs({ record: ctx.record, op: op, type: type, options: params })

        if (decoded === null) return false

        if (decoded.type === KEY && decoded.payload.state !== op.claim.meta.state) return false

        if (
          decoded.type === WRAPPING &&
          (await revoked({
            params: params,
            op: op,
            store: ctx.store,
            descriptors: decoded.payload.descriptors,
          }))
        )
          return false
      }

      if (
        !(await authorized(
          params,
          requestFor({
            op: op,
            record: ctx.record,
            store: ctx.store,
            transportContext: ctx.transportContext,
            verb: 'administer',
          }),
        ))
      )
        return false

      return (
        type !== WRAPPING ||
        !bindReceiver ||
        (await authorized(
          params,
          requestFor({
            op: op,
            record: ctx.record,
            store: ctx.store,
            transportContext: ctx.transportContext,
            verb: 'read',
          }),
        ))
      )
    },
    async visibleTo(record, ctx) {
      if (ctx.opKind !== params.opKind) return false

      const op = await verifySignedRecord({
        record: record,
        opKind: params.opKind,
        methods: params.methods,
        options: params,
      })

      if (
        op === null ||
        !(await validStructure(type, op, params)) ||
        !(await recordPayloadMatches(record, op.claim, params))
      )
        return false

      if (!op.claim.deleted) {
        const decoded = await decodedAs({ record: record, op: op, type: type, options: params })

        if (decoded === null) return false

        if (
          decoded.type === WRAPPING &&
          (await revoked({
            params: params,
            op: op,
            store: ctx.store,
            descriptors: decoded.payload.descriptors,
          }))
        )
          return false
      }

      return await authorized(
        params,
        requestFor({
          op: op,
          record: record,
          store: ctx.store,
          transportContext: ctx.transportContext,
          verb: 'read',
        }),
      )
    },
    async lockKeys(incoming, stored) {
      const keys = new Map<string, RecordLockKey>()
      const records = [incoming, ...(stored?.copies ?? [])]
      const ops = await Promise.all(
        records.map((record) => {
          return verifySignedRecord({
            record: record,
            opKind: params.opKind,
            methods: params.methods,
            options: params,
          })
        }),
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
      const op = await verifySignedRecord({
        record: record,
        opKind: params.opKind,
        methods: params.methods,
        options: params,
      })

      if (op === null) throw new Error('Applied record signature is invalid')

      await params
        .portsFor(store)
        .dropRevokedWrappings({ ownerDID: op.claim.owner, keyID: op.claim.meta.keyID as string })
    }
  }

  return definition
}

function captureParams<Params extends CryptoOptions & { methods?: MethodRegistry }>(input: Params) {
  const getter: (() => MethodRegistry | undefined) | undefined = Object.getOwnPropertyDescriptor(
    input,
    'methods',
  )?.get
  const methods = input.methods?.map((method) => {
    return {
      ...method,
      resolve: method.resolve.bind(method),
      resolveHistoric: method.resolveHistoric?.bind(method),
      resolveDenySet: method.resolveDenySet?.bind(method),
      resolveAgreementKey: method.resolveAgreementKey?.bind(method),
    }
  })
  return {
    ...input,
    crypto: input.crypto ?? nobleCrypto,
    // Store adapters supply an accessor bound to their current transaction.
    get methods() {
      return getter === undefined ? methods : getter.call(input)
    },
  }
}

/** One explicit replay domain and consumer policy for the five generic record types. */
export function vaultRecordTypes(input: VaultRecordTypeParams): Map<string, RecordTypeDefinition> {
  const params = captureParams(input)
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
  input: Pick<VaultRecordTypeParams, 'opKind' | 'methods' | 'crypto'>,
): VisibilityContext['currentKeyVersion'] {
  const params = captureParams(input)
  return async (owner, keyID) => {
    const stored = await store.get({ type: KEY, owner, id: keyID })
    const copy = stored?.copies[0]
    const op =
      copy === undefined
        ? null
        : await verifySignedRecord({
            record: copy,
            opKind: params.opKind,
            methods: params.methods,
            options: params,
          })
    const meta = op === null ? null : await vaultRecordMeta(KEY, op.claim, params)

    return op === null || meta === null || op.claim.deleted || op.claim.owner !== owner
      ? null
      : meta.version
  }
}

/** Proofs retain consumer authority checks but are never addressed to the local receiver. */
export function vaultProofAuthorizer(
  input: VaultRecordTypeParams,
  store: RecordStoreAdapter,
  transportContext?: unknown,
): VisibilityContext['authorizeProof'] {
  const params = captureParams(input)
  const wrapping = createType(WRAPPING, params, false)

  return async (record, stored) => {
    if (record.type !== WRAPPING) return false

    const op = await verifySignedRecord({
      record: record,
      opKind: params.opKind,
      methods: params.methods,
      options: params,
    })

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
