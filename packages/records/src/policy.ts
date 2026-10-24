import { compareRecordDecisionHLC, parseCanonicalHLC } from './clock.js'
import type { VerifiedRecordOp } from './op.js'
import { type RecordClaim, recordClaimDigest } from './record.js'

/**
 * How a record type orders two ops for one record.
 *
 * - `lww`: the greater `hlc` wins; a tie goes to the greater content digest. A delete orders like
 *   any other op.
 * - `monotonic`: the greater numeric version tuple wins. A type may explicitly choose
 *   `versionOrder: 'hlc'` to compare canonical string `meta.version` stamps instead. An equal
 *   version is decided by the `onEqual` hook, or by default goes to the greater content digest
 *   with a conflict reported.
 * - `immutable`: never replaced by an ordinary update. Two different ops under one id — a
 *   different payload, owner, meta, deletion flag or stamp — settle on the greater content digest
 *   with a conflict reported, since an id may be a natural key rather than a payload digest.
 */
export type MergePolicy =
  | { kind: 'lww' }
  | {
      kind: 'monotonic'
      version: (claim: RecordClaim) => ReadonlyArray<number>
      versionOrder?: 'hlc'
    }
  | { kind: 'immutable' }

/**
 * What a type's hook answers for two different ops at one version: `resolve` takes the
 * default greater-content-digest winner, `fork` keeps both as branches.
 */
export type EqualVersionDecision = 'resolve' | 'fork'

/**
 * The outcome of comparing an incoming op against a stored one.
 *
 * - `apply`: the incoming op replaces the stored one.
 * - `noop`: the stored op stays; the incoming one lost, or is the same op.
 * - `reject`: the incoming op is unusable against this record, whatever arrives later.
 * - `fork`: both ops are retained as branches.
 *
 * `conflict` names both ops whenever two different ops met at one version — whichever wins,
 * a rolled-back or duplicated counter must be visible rather than silently resolved.
 */
export type MergeDecision = {
  status: 'apply' | 'noop' | 'reject' | 'fork'
  reason?: string
  conflict?: { storedOpHash: string; incomingOpHash: string }
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

/** Greater content digest wins, so every arrival order stores the same decision. */
function byContentDigest(incoming: VerifiedRecordOp, stored: VerifiedRecordOp): 'apply' | 'noop' {
  return compareStrings(recordClaimDigest(incoming.claim), recordClaimDigest(stored.claim)) > 0
    ? 'apply'
    : 'noop'
}

function compareLWW(incoming: VerifiedRecordOp, stored: VerifiedRecordOp): MergeDecision {
  // A stamp that parses but is not canonical could carry any wall time its author liked past
  // a gate that only read the fields, so it never takes part in the ordering.
  const incomingStamp = parseCanonicalHLC(incoming.claim.hlc)
  if (incomingStamp === null) {
    return { status: 'reject', reason: 'hlc-not-canonical' }
  }
  const storedStamp = parseCanonicalHLC(stored.claim.hlc)
  if (storedStamp === null) {
    return { status: 'apply', reason: 'stored-hlc-not-canonical' }
  }
  const order = compareRecordDecisionHLC(incoming.claim.hlc, stored.claim.hlc)
  if (order !== 0) {
    return { status: order > 0 ? 'apply' : 'noop' }
  }
  return { status: byContentDigest(incoming, stored) }
}

/**
 * A monotonic op's version tuple, or `null` when the type's hook throws or answers anything
 * but finite numbers. Range order reads versions through this too, so it can never order an
 * op that apply would refuse.
 */
export function readVersion(
  version: (claim: RecordClaim) => ReadonlyArray<number>,
  claim: RecordClaim,
): ReadonlyArray<number> | null {
  let tuple: unknown
  try {
    tuple = version(claim)
  } catch {
    return null
  }
  if (!Array.isArray(tuple) || !tuple.every((part) => Number.isFinite(part))) {
    return null
  }
  return tuple as ReadonlyArray<number>
}

function readMonotonicVersion(
  policy: Extract<MergePolicy, { kind: 'monotonic' }>,
  claim: RecordClaim,
): ReadonlyArray<number> | null {
  const tuple = readVersion(policy.version, claim)
  if (
    tuple === null ||
    (policy.versionOrder === 'hlc' &&
      (typeof claim.meta.version !== 'string' || parseCanonicalHLC(claim.meta.version) === null))
  )
    return null
  return tuple
}

/** Lexicographic over numbers; a tuple extending an equal prefix is the greater. */
function compareTuples(left: ReadonlyArray<number>, right: ReadonlyArray<number>): number {
  const length = Math.min(left.length, right.length)
  for (let index = 0; index < length; index++) {
    const difference = (left[index] as number) - (right[index] as number)
    if (difference !== 0) {
      return difference
    }
  }
  return left.length - right.length
}

function compareMonotonic(
  incoming: VerifiedRecordOp,
  stored: VerifiedRecordOp,
  policy: Extract<MergePolicy, { kind: 'monotonic' }>,
  onEqual:
    | ((incoming: VerifiedRecordOp, stored: VerifiedRecordOp) => EqualVersionDecision)
    | undefined,
): MergeDecision {
  const incomingVersion = readMonotonicVersion(policy, incoming.claim)
  if (incomingVersion === null) {
    return { status: 'reject', reason: 'version-invalid' }
  }
  const storedVersion = readMonotonicVersion(policy, stored.claim)
  if (storedVersion === null) {
    return { status: 'apply', reason: 'stored-version-invalid' }
  }
  const order =
    policy.versionOrder === 'hlc'
      ? compareRecordDecisionHLC(
          incoming.claim.meta.version as string,
          stored.claim.meta.version as string,
        )
      : compareTuples(incomingVersion, storedVersion)
  if (order !== 0) {
    return { status: order > 0 ? 'apply' : 'noop' }
  }
  const conflict = { storedOpHash: stored.opHash, incomingOpHash: incoming.opHash }
  // The hook sees the pair in arrival order, so it must answer the same for (a, b) as for
  // (b, a): a hook that forks one way and resolves the other leaves one peer with both
  // branches and another with one.
  if (onEqual?.(incoming, stored) === 'fork') {
    return { status: 'fork', reason: 'equal-version-fork', conflict }
  }
  return { status: byContentDigest(incoming, stored), reason: 'equal-version-conflict', conflict }
}

/**
 * Rejecting the second op would keep whichever arrived first, so peers would diverge — and
 * peers syncing by decision digest must hold the same content even when rows read the same, or their
 * range fingerprints never agree. Callers get here only with two different ops.
 */
function compareImmutable(incoming: VerifiedRecordOp, stored: VerifiedRecordOp): MergeDecision {
  const conflict = { storedOpHash: stored.opHash, incomingOpHash: incoming.opHash }
  return { status: byContentDigest(incoming, stored), reason: 'immutable-conflict', conflict }
}

/**
 * A first write has nothing to lose to, but it must still be an op the policy can order: one
 * stored with a stamp or version no later op can compare against would yield to anything, and
 * so could be replaced by an op that would have lost to it.
 */
function admitFirstWrite(incoming: VerifiedRecordOp, policy: MergePolicy): MergeDecision {
  switch (policy.kind) {
    case 'lww':
      return parseCanonicalHLC(incoming.claim.hlc) === null
        ? { status: 'reject', reason: 'hlc-not-canonical' }
        : { status: 'apply' }
    case 'monotonic':
      return readMonotonicVersion(policy, incoming.claim) === null
        ? { status: 'reject', reason: 'version-invalid' }
        : { status: 'apply' }
    case 'immutable':
      return { status: 'apply' }
  }
}

/**
 * Decide whether an incoming op replaces the stored op for the same record, or, with no
 * stored op, whether it may be the record's first. Both must already be verified; this reads
 * only their claims and `opHash`, and assumes they address the same record. The same op
 * (equal `opHash`) is always a no-op, before any policy runs.
 *
 * Every policy is a total order over valid ops, so any arrival order of a set of ops — with
 * duplicates — leaves the same op stored. An incoming op the policy cannot order is rejected;
 * a stored one it cannot order yields to any incoming op it can.
 *
 * No drift bound applies here: each op is assumed to have already passed `parseBoundedHLC`.
 * This only refuses a non-canonical stamp, so a canonical far-future stamp that skipped that
 * gate would win every `lww` comparison.
 *
 * `onEqual` must be symmetric — the same answer for (a, b) as for (b, a) — or peers that saw
 * the two ops in opposite orders split.
 */
export function compareRecordOps(
  incoming: VerifiedRecordOp,
  stored: VerifiedRecordOp | null,
  policy: MergePolicy,
  onEqual?: (incoming: VerifiedRecordOp, stored: VerifiedRecordOp) => EqualVersionDecision,
): MergeDecision {
  if (stored === null) {
    return admitFirstWrite(incoming, policy)
  }
  if (incoming.opHash === stored.opHash) {
    return { status: 'noop' }
  }
  switch (policy.kind) {
    case 'lww':
      return compareLWW(incoming, stored)
    case 'monotonic':
      return compareMonotonic(incoming, stored, policy, onEqual)
    case 'immutable':
      return compareImmutable(incoming, stored)
  }
}
