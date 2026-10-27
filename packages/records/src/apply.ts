import type { MethodRegistry } from '@kokuin/token'
import type { HLCTimestamp } from '@sozai/hlc'

import { parseBoundedHLC } from './clock.js'
import type { RecordDecision } from './decision.js'
import { settleLimited } from './limit.js'
import { createRecordVerifier, type VerifiedRecordOp, verifySignedRecord } from './op.js'
import { compareRecordOps, type EqualVersionDecision, type MergePolicy } from './policy.js'
import {
  type RecordKey,
  recordClaimDigest,
  recordPayloadMatches,
  recordSignerKey,
  type SignedRecord,
} from './record.js'
import {
  getRecordDecisions,
  type RecordDecisionMap,
  type RecordLockKey,
  type RecordStoreAdapter,
  recordKeyText,
} from './store.js'

/** The authenticated peer asking for records, and the controller it acts for, if any. */
export type RecordRequester = { peerDID: string; controllerDID: string | null }

/**
 * What a responding peer knows when it decides whether a requester may receive a record.
 *
 * - `proofs` are records the requester presented as its own, such as its wrapping of a key.
 *   They are hostile input: the responder checks them and never stores or forwards them.
 * - `store` is the responder's own store, read for its holdings and for proof dependencies.
 * - `authorizeProof` is the authorizer apply would run on the proof, bound to the resolvers
 *   and to this context's `store`, which it passes as the authorizer's `store`.
 *   `stored` is the responder's verified row for the proof's record, or `null` when it holds
 *   none, as apply passes it.
 * - `currentKeyVersion` is the responder's current version of the key `keyID` of `owner` (a
 *   normalized DID), `null` when it holds none. A key id names a key only within its owner.
 * - `holderTypes` are the types whose records show that their recipient holds a key, keyed by
 *   type; a proof's dependencies come from its definition. A record of any other type is
 *   never a holding, whatever its `meta` says, so a revocation naming a key and a recipient
 *   cannot pass for a wrapping. Empty, no one is a key holder.
 */
export type VisibilityContext = {
  requester: RecordRequester
  opKind: string
  /** Caller-owned transport state, passed unchanged and never signed. */
  transportContext?: unknown
  proofs: ReadonlyArray<SignedRecord>
  store: RecordStoreAdapter
  authorizeProof: (record: SignedRecord, stored: SignedRecord | null) => Promise<boolean>
  currentKeyVersion: (owner: string, keyID: string) => Promise<number | null>
  isGroupMember: (groupID: string, did: string) => Promise<boolean>
  holderTypes: ReadonlyMap<string, RecordTypeDefinition>
  methods?: MethodRegistry
}

/**
 * What an authorizer reads beside the verified op.
 *
 * - `record` is the record being authorized. Its payload has not been checked against the
 *   signed digest yet: an authorizer that reads the payload must call `recordPayloadMatches`
 *   first, or it reasons over bytes nobody signed.
 * - `stored` is the record's current verified row, or `null` on a first write.
 * - `store` is the store the decision runs against: the chunk's transaction in apply, the
 *   responder's store for a holder proof. An authorizer reads other records through it,
 *   never through a store bound outside the transaction.
 */
export type RecordReceiveContext = {
  /** Caller-owned transport state, passed unchanged and never signed. */
  transportContext?: unknown
}

export type RecordAuthorizeContext = RecordReceiveContext & {
  record: SignedRecord
  stored: SignedRecord | null
  store: RecordStoreAdapter
  /**
   * Another record's decision as the chunk has left it, records stored earlier in the chunk
   * included. Apply serves it from the chunk's batched reads. Absent outside apply: read
   * `store` instead.
   */
  decision?: (key: RecordKey) => Promise<RecordDecision | null>
  resolveController: (did: string) => Promise<string | null>
  verifyCapability: (
    tokens: ReadonlyArray<string>,
    owner: string,
    issuer: string,
  ) => Promise<boolean>
}

/**
 * A record this one needs before it can be authorized. It is satisfied when the store holds
 * a verified op for `(type, id)` and, if given, `satisfiedBy` accepts that op — a wrapping for
 * key version 3 is not satisfied by version 2 of the key. An unsatisfied dependency parks the
 * record, the same as a missing one, until a later op satisfies it.
 */
export type RecordDependency = RecordKey & {
  satisfiedBy?: (stored: VerifiedRecordOp) => boolean
}

/**
 * How the apply engine treats one record type.
 *
 * - `authorize` decides whether the op's verified issuer may write this record. `stored` is
 *   the record's current op, or `null` on a first write. The engine itself refuses an owner
 *   change under `lww` and `monotonic`, whatever `authorize` answers. `immutable` skips this
 *   owner-continuity check. Owner-qualified keys keep different owners' records separate.
 *   WARNING: bind `claim.owner` to the owner of the record an immutable record depends on.
 *   Checking only the issuer against `claim.owner` can admit a dependent under the wrong owner.
 * - `precheck` is a stateless issuer and signed-shape check before dependencies are read.
 * - `dependsOn` lists the types whose records this one may need, and orders a chunk.
 * - `dependencies` names the exact records this one needs before it can be authorized. It
 *   runs only after the signature has verified, and should read the signed claim in `op`:
 *   the payload is not checked against its digest until after the merge decision.
 * - `onEqual` must answer the same for (a, b) as for (b, a).
 * - `afterApply` runs inside the chunk's transaction, once the record is stored.
 *
 * Apply keeps every decision it reads for the rest of the chunk and updates it with its own
 * writes. Hooks may write other state through the store, never a record decision.
 */
export type RecordTypeDefinition = {
  type: string
  policy: MergePolicy
  dependsOn: ReadonlyArray<string>
  /**
   * Whether the op's issuer may write this record. For an `immutable` type the engine skips
   * the owner-continuity check, so this must bind `op.claim.owner` to the owner of the
   * record it depends on.
   */
  authorize(op: VerifiedRecordOp, ctx: RecordAuthorizeContext): Promise<boolean>
  precheck?: (op: VerifiedRecordOp, record: SignedRecord) => Promise<boolean>
  visibleTo?: (record: SignedRecord, ctx: VisibilityContext) => Promise<boolean>
  dependencies(record: SignedRecord, op: VerifiedRecordOp): ReadonlyArray<RecordDependency>
  onEqual?: (incoming: VerifiedRecordOp, stored: VerifiedRecordOp) => EqualVersionDecision
  afterApply?: (record: SignedRecord, store: RecordStoreAdapter) => Promise<void>
  /** Retain authenticated branch evidence even when the merge keeps another current op. */
  afterAuthorize?: (record: SignedRecord, store: RecordStoreAdapter) => Promise<void>
  /** Keys this write can affect; `stored` is a speculative read before the chunk locks. */
  lockKeys?: (
    incoming: SignedRecord,
    stored: RecordDecision | null,
  ) => ReadonlyArray<RecordLockKey> | Promise<ReadonlyArray<RecordLockKey>>
}

/**
 * Two different ops met at one version of a record. `record` is the incoming one; whichever
 * op won is the one the store now holds. `forked` when the type's `onEqual` hook kept both as
 * branches: the store still holds only the greater `opHash`, and retaining the other branch
 * is the type's work.
 */
export type RecordConflict = {
  record: SignedRecord
  storedOpHash: string
  incomingOpHash: string
  forked: boolean
}

/**
 * - `applied`: records stored by this chunk.
 * - `parked`: records whose dependencies are not stored, or not yet satisfied. They passed the clock and
 *   signature and precheck checks; the caller keeps them and passes them to a later
 *   chunk or session, since another peer may hold the dependency.
 * - `rejected`: `reason` is the first check that failed — `clock`, `unknown-type`,
 *   `signature`, `owner`, `unauthorized`, the policy's own reason (such as `version-invalid`),
 *   or `digest`.
 * - `conflicts`: every equal-version meeting of two different ops, in either outcome.
 *
 * A record that loses the merge, or repeats the stored op, appears in none of them.
 */
export type ApplyResult = {
  applied: number
  parked: Array<SignedRecord>
  rejected: Array<{ record: SignedRecord; reason: string }>
  conflicts: Array<RecordConflict>
}

export type ApplyRecordChunkParams = RecordReceiveContext & {
  opKind: string
  records: ReadonlyArray<SignedRecord>
  store: RecordStoreAdapter
  types: ReadonlyMap<string, RecordTypeDefinition>
  nowMS: number
  maxDriftMS: number
  receiveClock: (stamp: HLCTimestamp) => void
  methods?: MethodRegistry
  /** Called for several DIDs at once before the chunk locks; must accept concurrent calls. */
  resolveController: (did: string) => Promise<string | null>
  verifyCapability: (
    tokens: ReadonlyArray<string>,
    owner: string,
    issuer: string,
  ) => Promise<boolean>
}

/** Thrown when the registered types' `dependsOn` is cyclic or names an unregistered type. */
export class RecordTypeGraphError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RecordTypeGraphError'
  }
}

/** A speculative lock set changed; an ambient transaction must roll back before retrying. */
export class RecordSourceChangedError extends Error {
  constructor() {
    super('Record source changed while acquiring locks')
    this.name = 'RecordSourceChangedError'
  }
}

/** A type hook refused one signed record's content permanently. */
export class RecordContentRefusalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RecordContentRefusalError'
  }
}

/** Each type's position in an order where every type comes after the types it depends on. */
function rankTypes(types: ReadonlyMap<string, RecordTypeDefinition>): Map<string, number> {
  const ranks = new Map<string, number>()
  const visiting = new Set<string>()
  const visit = (type: string): void => {
    if (ranks.has(type)) {
      return
    }
    const definition = types.get(type)
    if (definition === undefined) {
      throw new RecordTypeGraphError(`Record type ${type} is not registered`)
    }
    if (visiting.has(type)) {
      throw new RecordTypeGraphError(`Record type ${type} depends on itself`)
    }
    visiting.add(type)
    for (const dependency of definition.dependsOn) {
      visit(dependency)
    }
    visiting.delete(type)
    ranks.set(type, ranks.size)
  }
  for (const type of types.keys()) {
    visit(type)
  }
  return ranks
}

/** A record that passed the clock and signature checks. */
type Candidate = {
  record: SignedRecord
  op: VerifiedRecordOp
  stamp: HLCTimestamp
  definition: RecordTypeDefinition
}

/** Each candidate's `dependencies` answer, asked once per chunk: it reads only the signed op. */
type DependencyLists = Map<Candidate, ReadonlyArray<RecordDependency>>

/** What one transactional pass over a chunk of candidates settled. */
type ProcessedChunk = {
  applied: Array<Candidate>
  conflicts: Array<RecordConflict>
  refused: ApplyResult['rejected']
  parked: Array<Candidate>
}

type Outcome =
  | { status: 'applied' | 'noop' | 'parked'; conflict?: RecordConflict }
  | { status: 'rejected'; reason: string }

type ChunkContext = RecordReceiveContext & {
  opKind: string
  tx: RecordStoreAdapter
  resolveController: ApplyRecordChunkParams['resolveController']
  verifyCapability: ApplyRecordChunkParams['verifyCapability']
  methods?: MethodRegistry
  decisions: Map<string, DecisionSnapshot>
  dependencies: DependencyLists
  /** Verifies each distinct op token once in this transaction. */
  verify: (record: SignedRecord) => Promise<VerifiedRecordOp | null>
  /** Why the batched read failed, if it did. */
  prefetchError?: unknown
}

type DecisionSnapshot = {
  decision: RecordDecision | null
  verified: Array<{ copy: SignedRecord; op: VerifiedRecordOp | null }>
  checkedPrior: boolean
}

async function snapshotOf(
  decision: RecordDecision | null,
  ctx: ChunkContext,
): Promise<DecisionSnapshot> {
  const verified = await Promise.all(
    (decision?.copies ?? []).map(async (copy) => ({
      copy,
      op: await ctx.verify(copy),
    })),
  )
  return { decision, verified, checkedPrior: false }
}

async function decisionSnapshot(key: RecordKey, ctx: ChunkContext): Promise<DecisionSnapshot> {
  const id = recordKeyText(key)
  const cached = ctx.decisions.get(id)
  if (cached !== undefined) return cached
  let decision: RecordDecision | null
  try {
    decision = await ctx.tx.get(key)
  } catch (error) {
    // After a failed batch, its error is the store's first failure in this transaction. On a
    // store where a failed statement aborts the transaction, this read only reports that.
    throw ctx.prefetchError ?? error
  }
  const snapshot = await snapshotOf(decision, ctx)
  ctx.decisions.set(id, snapshot)
  return snapshot
}

/**
 * Loads the decisions of `keys` the chunk has not read yet, in one batched read. `known` holds
 * decisions already read in this transaction. A failed batch seeds nothing: each key is then
 * read on first use, and a failing read there reports the batch's error.
 */
async function prefetchSnapshots(
  keys: ReadonlyArray<RecordKey>,
  ctx: ChunkContext,
  known: RecordDecisionMap,
  knownKeys: ReadonlySet<string>,
): Promise<void> {
  const missing = new Map<string, RecordKey>()
  for (const key of keys) {
    const id = recordKeyText(key)
    if (!ctx.decisions.has(id) && !knownKeys.has(id)) missing.set(id, key)
  }
  let loaded: RecordDecisionMap = new Map()
  try {
    loaded = await getRecordDecisions(ctx.tx, [...missing.values()])
  } catch (error) {
    // Kept, not dropped: a later single read that fails reports this original error.
    ctx.prefetchError = error
    missing.clear()
  }
  const ids = [...new Set([...knownKeys, ...missing.keys()])].filter((id) => !ctx.decisions.has(id))
  const snapshots = await Promise.all(
    ids.map((id) => snapshotOf((knownKeys.has(id) ? known : loaded).get(id) ?? null, ctx)),
  )
  for (const [index, id] of ids.entries()) {
    const snapshot = snapshots[index]
    if (snapshot !== undefined) ctx.decisions.set(id, snapshot)
  }
}

/** The decision a store read would return now: copies follow pruning as well as storing. */
function currentDecision(snapshot: DecisionSnapshot): RecordDecision | null {
  if (snapshot.decision === null) return null
  return { ...snapshot.decision, copies: snapshot.verified.map(({ copy }) => copy) }
}

function rememberCopy(
  snapshot: DecisionSnapshot,
  record: SignedRecord,
  op: VerifiedRecordOp,
): void {
  const decision = snapshot.decision
  const signer = recordSignerKey(op.issuer, record.opJWT)
  const retained = snapshot.verified.filter(({ copy, op: previous }) => {
    if (previous === null || signer === null) return true
    return recordSignerKey(previous.issuer, copy.opJWT) !== signer || copy.opHash < record.opHash
  })
  if (
    signer !== null &&
    retained.some(
      ({ copy, op: previous }) =>
        previous !== null &&
        recordSignerKey(previous.issuer, copy.opJWT) === signer &&
        copy.opHash <= record.opHash,
    )
  )
    return
  snapshot.verified = [...retained, { copy: record, op }]
  snapshot.decision = {
    key: { type: record.type, owner: record.owner, id: record.id },
    decisionHLC: typeof op.claim.meta.version === 'string' ? op.claim.meta.version : op.claim.hlc,
    contentDigest: recordClaimDigest(op.claim),
    copies: snapshot.verified.map(({ copy }) => copy),
  }
  if (decision === null) snapshot.checkedPrior = true
}

/** Whether the store lacks a dependency, or holds an op for it that does not satisfy it. */
export async function isDependencyUnsatisfied(
  dependency: RecordDependency,
  tx: RecordStoreAdapter,
  opKind: string,
  methods?: MethodRegistry,
): Promise<boolean> {
  return await isDependencyUnsatisfiedBy(dependency, await tx.get(dependency), opKind, methods)
}

/** As {@link isDependencyUnsatisfied}, against a decision already read. */
export async function isDependencyUnsatisfiedBy(
  dependency: RecordDependency,
  stored: RecordDecision | null,
  opKind: string,
  methods?: MethodRegistry,
): Promise<boolean> {
  if (stored === null || stored.key.owner !== dependency.owner) return true
  // Verification never throws, so every copy is checked together, then matched in order.
  const ops = await Promise.all(
    stored.copies.map((copy) => verifySignedRecord(copy, opKind, methods)),
  )
  return !ops.some(
    (op) =>
      op?.claim.type === dependency.type &&
      op.claim.owner === dependency.owner &&
      op.claim.id === dependency.id &&
      (dependency.satisfiedBy?.(op) ?? true),
  )
}

async function isParked(candidate: Candidate, ctx: ChunkContext): Promise<boolean> {
  const dependencies =
    ctx.dependencies.get(candidate) ??
    candidate.definition.dependencies(candidate.record, candidate.op)
  for (const dependency of dependencies) {
    // The chunk's view, as `isDependencyUnsatisfied` would read it from the store now.
    const snapshot = await decisionSnapshot(dependency, ctx)
    const stored = currentDecision(snapshot)
    const satisfied =
      stored !== null &&
      stored.key.owner === dependency.owner &&
      snapshot.verified.some(
        ({ op }) =>
          op?.claim.type === dependency.type &&
          op.claim.owner === dependency.owner &&
          op.claim.id === dependency.id &&
          (dependency.satisfiedBy?.(op) ?? true),
      )
    if (!satisfied) {
      return true
    }
  }
  return false
}

/** Checks three to five, against the store as the chunk has left it so far. */
async function applyCandidate(candidate: Candidate, ctx: ChunkContext): Promise<Outcome> {
  const { record, op, definition } = candidate
  const { tx } = ctx
  const key: RecordKey = { type: op.claim.type, owner: op.claim.owner, id: op.claim.id }
  const snapshot = await decisionSnapshot(key, ctx)
  const storedDecision = snapshot.decision
  if (storedDecision?.copies.some((copy) => copy.opHash === record.opHash)) {
    return { status: 'noop' }
  }
  if (await isParked(candidate, ctx)) {
    return { status: 'parked' }
  }
  // A stored op that no longer verifies is not a record, so it binds no owner and yields to
  // any incoming op, as the policy treats a stored op it cannot order.
  const storedRecord = storedDecision?.copies[0] ?? null
  const storedOp = storedRecord === null ? null : (snapshot.verified[0]?.op ?? null)
  const stored = storedOp === null ? null : storedRecord

  // Owner binding holds even against a permissive authorizer. Under `immutable`, two ops
  // with different owners are a conflict that the policy settles instead.
  if (
    storedOp !== null &&
    definition.policy.kind !== 'immutable' &&
    op.claim.owner !== storedOp.claim.owner
  ) {
    return { status: 'rejected', reason: 'owner' }
  }
  const decision = async (dependency: RecordKey) => {
    return currentDecision(await decisionSnapshot(dependency, ctx))
  }
  const authorized = await definition.authorize(op, {
    record,
    stored,
    store: tx,
    decision,
    transportContext: ctx.transportContext,
    resolveController: ctx.resolveController,
    verifyCapability: ctx.verifyCapability,
  })
  if (!authorized) {
    return { status: 'rejected', reason: 'unauthorized' }
  }

  if (definition.afterAuthorize !== undefined) {
    if (!recordPayloadMatches(record, op.claim)) {
      return { status: 'rejected', reason: 'digest' }
    }
    await definition.afterAuthorize(record, tx)
  }

  if (
    storedDecision !== null &&
    storedDecision !== undefined &&
    storedDecision.contentDigest === recordClaimDigest(op.claim) &&
    storedDecision.decisionHLC ===
      (typeof op.claim.meta.version === 'string' ? op.claim.meta.version : op.claim.hlc)
  ) {
    if (!recordPayloadMatches(record, op.claim)) return { status: 'rejected', reason: 'digest' }
    await tx.putCopy(record)
    if (!snapshot.checkedPrior)
      for (const { copy, op: previous } of snapshot.verified) {
        if (
          previous !== null &&
          previous.issuer !== op.issuer &&
          !(await definition.authorize(previous, {
            record: copy,
            stored: record,
            store: tx,
            decision,
            transportContext: ctx.transportContext,
            resolveController: ctx.resolveController,
            verifyCapability: ctx.verifyCapability,
          }))
        ) {
          await tx.pruneCopy(key, previous.issuer)
          snapshot.verified = snapshot.verified.filter(
            ({ op: held }) => held?.issuer !== previous.issuer,
          )
        }
      }
    snapshot.checkedPrior = true
    rememberCopy(snapshot, record, op)
    return { status: 'applied' }
  }

  const merge = compareRecordOps(op, storedOp, definition.policy, definition.onEqual)
  if (merge.status === 'reject') {
    return { status: 'rejected', reason: merge.reason ?? 'policy' }
  }
  const conflict: RecordConflict | undefined =
    merge.conflict === undefined
      ? undefined
      : { record, ...merge.conflict, forked: merge.status === 'fork' }
  // A fork still needs one op in the store, and the same one on every peer.
  const wins =
    merge.status === 'apply' ||
    (merge.status === 'fork' &&
      storedOp !== null &&
      recordClaimDigest(op.claim) > recordClaimDigest(storedOp.claim))
  if (!wins) {
    return { status: 'noop', conflict }
  }

  if (!recordPayloadMatches(record, op.claim)) {
    return { status: 'rejected', reason: 'digest' }
  }
  await tx.putCopy(record)
  snapshot.decision = null
  snapshot.verified = []
  rememberCopy(snapshot, record, op)
  await definition.afterApply?.(record, tx)
  return { status: 'applied', conflict }
}

class RefusedCandidate extends Error {
  #candidate: Candidate

  constructor(candidate: Candidate, options: ErrorOptions) {
    super('Record content refused', options)
    this.name = 'RefusedCandidate'
    this.#candidate = candidate
  }

  get candidate(): Candidate {
    return this.#candidate
  }
}

/**
 * Apply a chunk of records received from a peer, in one transaction.
 *
 * Each record passes checks in order, and stops at the first it fails:
 * 1. its `hlc` is canonical and within `maxDriftMS` of `nowMS`;
 * 2. its op verifies, and signs exactly the record's `type`, `id`, `owner`, `hlc` and
 *    `opHash`;
 * 3. its type's stateless precheck accepts the issuer, before dependency lookup;
 * 4. dependencies are present and satisfied, or the record parks;
 * 5. its type's authorizer accepts the issuer after the owner binding;
 * 6. its type's merge policy prefers it to the stored op, or admits it as a first write;
 * 7. its payload matches the signed digest.
 *
 * Nothing about a record is read before the first check — not the store, not its signature
 * — and `receiveClock` advances the local clock from stored records after the chunk's
 * transaction returns. An owned transaction has committed at that point. Inside a
 * caller-owned transaction, apply advances `receiveClock` before the enclosing transaction
 * commits. Callers needing commit-only clock effects must defer them until that commit.
 * Records apply in the types' dependency order; one whose dependencies are not
 * stored or not yet satisfied is retried after each pass that stored something, and returned
 * as parked when a pass stores nothing.
 *
 * An error from the store, a hook or a resolver rolls the chunk back and propagates. A type
 * hook may use `RecordContentRefusalError` for a deterministic refusal of one record's content.
 *
 * @throws RecordTypeGraphError when the types' dependencies are cyclic or unregistered.
 * @throws RecordSourceChangedError when a changed lock set requires an ambient transaction
 * to roll back, or five owned transaction attempts all observe a changed lock set.
 */
export async function applyRecordChunk(params: ApplyRecordChunkParams): Promise<ApplyResult> {
  const { records, store, types, nowMS, maxDriftMS, receiveClock } = params
  const ranks = rankTypes(types)
  const verify = createRecordVerifier(params.opKind, params.methods)
  const rejected: ApplyResult['rejected'] = []
  const candidates: Array<Candidate> = []
  // Refused records await one batched read of the store, which may show them as replays.
  const refusedReplays: Array<SignedRecord> = []
  // The clock and type checks run first for every record. Signatures of the records that pass
  // them are verified together, since verification never throws; the rest runs in record order.
  const screened = records.map((record) => {
    const stamp = parseBoundedHLC(record.hlc, nowMS, maxDriftMS)
    const definition = stamp === null ? undefined : types.get(record.type)
    return {
      record,
      stamp,
      definition,
      verifying: definition === undefined ? null : verify(record),
    }
  })
  for (const { record, stamp, definition, verifying } of screened) {
    if (stamp === null) {
      rejected.push({ record, reason: 'clock' })
      continue
    }
    if (definition === undefined || verifying === null) {
      rejected.push({ record, reason: 'unknown-type' })
      continue
    }
    const op = await verifying
    if (op === null) {
      rejected.push({ record, reason: 'signature' })
      continue
    }
    // Stateless refusal must precede authority reads, locks and dependencies.
    try {
      if (definition.precheck !== undefined && !(await definition.precheck(op, record))) {
        refusedReplays.push(record)
        rejected.push({ record, reason: 'unauthorized' })
        continue
      }
    } catch (error) {
      if (!(error instanceof RecordContentRefusalError) || store.isTransaction === true) throw error
      rejected.push({ record, reason: 'content-refused' })
      continue
    }
    candidates.push({ record, op, stamp, definition })
  }
  if (refusedReplays.length > 0) {
    // A replay stays a no-op even if its issuer or content is no longer admissible.
    const stored = await getRecordDecisions(store, refusedReplays)
    const replays = new Set(
      refusedReplays.filter((record) =>
        stored.get(recordKeyText(record))?.copies.some((copy) => copy.opHash === record.opHash),
      ),
    )
    if (replays.size > 0) {
      const kept = rejected.filter((entry) => !replays.has(entry.record))
      rejected.splice(0, rejected.length, ...kept)
    }
  }
  // Stable, so records of one type keep their arrival order.
  candidates.sort(
    (left, right) =>
      (ranks.get(left.record.type) as number) - (ranks.get(right.record.type) as number),
  )

  let outcome: ProcessedChunk | undefined
  async function processChunk(active: ReadonlyArray<Candidate>): Promise<ProcessedChunk> {
    const expected = new Map<Candidate, Array<RecordLockKey>>()
    const allKeys = new Map<string, RecordLockKey>()
    const controllers = new Map<string, Promise<string | null>>()
    const prefetched = await getRecordDecisions(
      store,
      active.map((candidate) => candidate.record),
    )
    const verifiedStored = new Map<string, Promise<void>>()
    const prefetchController = async (did: string): Promise<void> => {
      let resolving = controllers.get(did)
      if (resolving === undefined) {
        resolving = params.resolveController(did)
        controllers.set(did, resolving)
      }
      await resolving
    }
    const verifyStored = async (id: string): Promise<void> => {
      await Promise.all(
        (prefetched.get(id)?.copies ?? []).map(async (copy) => {
          const op = await verify(copy)
          if (op !== null && op.issuer !== op.claim.owner) await prefetchController(op.issuer)
        }),
      )
    }
    // Each candidate's controller and stored-copy reads run together, up to `CONCURRENCY_LIMIT`
    // at once, and shared reads are made once. The lock-key hooks then run one at a time, in
    // candidate order, as before. Failures are thrown in candidate order: a candidate's reads,
    // then its hook.
    const reads = await settleLimited(active, async (candidate) => {
      if (candidate.op.issuer !== candidate.op.claim.owner) {
        await prefetchController(candidate.op.issuer)
      }
      const id = recordKeyText(candidate.record)
      let storedChecked = verifiedStored.get(id)
      if (storedChecked === undefined) {
        storedChecked = verifyStored(id)
        verifiedStored.set(id, storedChecked)
      }
      await storedChecked
    })
    for (const [index, candidate] of active.entries()) {
      const read = reads[index]
      if (read?.status === 'rejected') throw read.reason
      const hook = candidate.definition.lockKeys
      if (hook === undefined) continue
      const stored = prefetched.get(recordKeyText(candidate.record)) ?? null
      const keys = [
        ...new Map(
          (await hook(candidate.record, stored)).map((key) => [
            JSON.stringify([key.type, key.key]),
            key,
          ]),
        ).values(),
      ].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
      expected.set(candidate, keys)
      for (const key of keys) allKeys.set(JSON.stringify([key.type, key.key]), key)
    }
    return await store.transaction(async (tx) => {
      if (allKeys.size > 0 && tx.lock === undefined) {
        throw new Error('Record store does not support transaction key locks')
      }
      if (allKeys.size > 0)
        await tx.lock?.(
          [...allKeys.values()].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
        )
      // Re-read under the locks: the prefetch above ran before them.
      const checked = await getRecordDecisions(
        tx,
        [...expected.keys()].map((candidate) => candidate.record),
      )
      for (const [candidate, keys] of expected) {
        const stored = checked.get(recordKeyText(candidate.record)) ?? null
        const current = [
          ...new Map(
            ((await candidate.definition.lockKeys?.(candidate.record, stored)) ?? []).map((key) => [
              JSON.stringify([key.type, key.key]),
              key,
            ]),
          ).keys(),
        ].sort()
        const original = keys.map((key) => JSON.stringify([key.type, key.key])).sort()
        if (
          current.length !== original.length ||
          current.some((key, index) => key !== original[index])
        ) {
          throw new RecordSourceChangedError()
        }
      }
      const ctx: ChunkContext = {
        tx,
        opKind: params.opKind,
        transportContext: params.transportContext,
        resolveController: async (did) =>
          await (controllers.get(did) ?? params.resolveController(did)),
        verifyCapability: params.verifyCapability,
        methods: params.methods,
        decisions: new Map(),
        dependencies: new Map(
          active.map((candidate) => [
            candidate,
            candidate.definition.dependencies(candidate.record, candidate.op),
          ]),
        ),
        // A fresh scope per transaction: a resolved issuer's key removed before the locks must
        // not pass on a verification made before them. Self-certifying issuers still hit the
        // process-wide memo.
        verify: createRecordVerifier(params.opKind, params.methods),
      }
      // One batched read for every decision the chunk will consult: each record's own and its
      // dependencies'. Writes made by this chunk update these snapshots in place.
      await prefetchSnapshots(
        active.flatMap((candidate) => [
          candidate.record,
          ...(ctx.dependencies.get(candidate) ?? []),
        ]),
        ctx,
        checked,
        new Set([...expected.keys()].map((candidate) => recordKeyText(candidate.record))),
      )
      const applied: Array<Candidate> = []
      const conflicts: Array<RecordConflict> = []
      const refused: ApplyResult['rejected'] = []
      let pending = [...active]
      for (;;) {
        const parked: Array<Candidate> = []
        const appliedBefore = applied.length
        for (const candidate of pending) {
          let result: Outcome
          try {
            result = await applyCandidate(candidate, ctx)
          } catch (error) {
            if (error instanceof RecordContentRefusalError)
              throw new RefusedCandidate(candidate, { cause: error })
            throw error
          }
          if (result.status === 'rejected') {
            refused.push({ record: candidate.record, reason: result.reason })
            continue
          }
          if (result.conflict !== undefined) {
            conflicts.push(result.conflict)
          }
          if (result.status === 'applied') {
            applied.push(candidate)
          } else if (result.status === 'parked') {
            parked.push(candidate)
          }
        }
        // Parking reads only the store, so a pass that stored nothing parks the same records.
        if (parked.length === 0 || applied.length === appliedBefore) {
          return { applied, conflicts, refused, parked }
        }
        pending = parked
      }
    })
  }
  let active = [...candidates]
  const contentRefused: ApplyResult['rejected'] = []
  let sourceRetries = 0
  for (let attempt = 0; attempt < candidates.length + 5; attempt += 1) {
    try {
      outcome = await processChunk(active)
      break
    } catch (error) {
      if (error instanceof RefusedCandidate && store.isTransaction === true) {
        throw error.cause
      }
      if (error instanceof RefusedCandidate && store.isTransaction !== true) {
        contentRefused.push({ record: error.candidate.record, reason: 'content-refused' })
        active = active.filter((candidate) => candidate !== error.candidate)
        continue
      }
      if (!(error instanceof RecordSourceChangedError) || store.isTransaction === true) throw error
      sourceRetries += 1
      if (sourceRetries >= 5) throw error
    }
  }
  if (outcome === undefined) throw new RecordSourceChangedError()

  for (const candidate of outcome.applied) {
    receiveClock(candidate.stamp)
  }
  return {
    applied: outcome.applied.length,
    parked: outcome.parked.map((candidate) => candidate.record),
    rejected: [...rejected, ...contentRefused, ...outcome.refused],
    conflicts: outcome.conflicts,
  }
}
