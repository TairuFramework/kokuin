import { normalizeDID } from '@kokuin/token'

import {
  isDependencyUnsatisfied,
  type RecordTypeDefinition,
  type VisibilityContext,
} from './apply.js'
import { type VerifiedRecordOp, verifySignedRecord } from './op.js'
import { compareRecordOps } from './policy.js'
import {
  type RecordClaim,
  recordClaimDigest,
  recordPayloadMatches,
  type SignedRecord,
} from './record.js'

/**
 * A built-in visibility rule. Each reads the record's verified claim:
 *
 * - `ownerDevices`: the requester's peer DID, or the controller it acts for, is the record's
 *   `owner`.
 * - `recipient`: `meta.recipient` names the requester's peer DID.
 * - `keyHolder`: the requester holds a live wrapping of the key named by `meta.keyID`, at the
 *   responder's current version of it. The holding is a record of one of
 *   `VisibilityContext.holderTypes` that passes `verifyHolderProof`: either one the responder
 *   stores, or one the requester presented as a proof, with the same `owner` as the record:
 *   a key id names a key only within its owner. A holding record carries `meta.keyID` (a
 *   string), `meta.keyVersion` (a non-negative safe integer) and `meta.recipient` (a DID). A
 *   guarded record that carries `meta.keyVersion` must carry a valid one.
 * - `sharedWith`: `meta.sharedWith` (an array of DIDs) names the requester's peer DID or its
 *   controller, or the requester is a member of a group in `meta.sharedWithGroups` (an array
 *   of group ids). A member that is not a string is ignored.
 *
 * A field of the wrong shape satisfies no rule.
 */
export type VisibilityRule = 'ownerDevices' | 'recipient' | 'keyHolder' | 'sharedWith'

function normalizedOrNull(did: string | null): string | null {
  if (typeof did !== 'string') {
    return null
  }
  try {
    return normalizeDID(did)
  } catch {
    return null
  }
}

function namesDID(value: unknown, did: string | null): boolean {
  const target = normalizedOrNull(did)
  return typeof value === 'string' && target !== null && normalizedOrNull(value) === target
}

function stringsIn(value: unknown): Array<string> {
  return Array.isArray(value)
    ? value.filter((member): member is string => typeof member === 'string')
    : []
}

/** A key version: a non-negative safe integer, so ordering it against another is exact. */
function isKeyVersion(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0
}

/** The key a holding proves the requester holds, and whose key it is. */
type Holding = { keyID: string; owner: string }

/**
 * Whether the responder's stored row for a proof's record leaves the proof standing: none,
 * one that no longer verifies (apply treats it as absent too), or a live row of the same
 * owner that does not order after the proof. A responder behind the requester still admits
 * the newer proof.
 */
function storedRowAdmits(
  proof: VerifiedRecordOp,
  stored: VerifiedRecordOp | null,
  definition: RecordTypeDefinition,
): boolean {
  if (stored === null) {
    return true
  }
  if (stored.claim.owner !== proof.claim.owner || stored.claim.deleted) {
    return false
  }
  if (stored.opHash === proof.opHash) {
    return true
  }
  if (recordClaimDigest(stored.claim) === recordClaimDigest(proof.claim)) {
    return true
  }
  // The same winner apply would store: the proof must be the op a merge keeps.
  const decision = compareRecordOps(proof, stored, definition.policy, definition.onEqual)
  return (
    decision.status === 'apply' ||
    (decision.status === 'fork' && recordClaimDigest(proof.claim) > recordClaimDigest(stored.claim))
  )
}

/** What a holding record proves the requester holds, or `null` when it proves nothing. */
async function heldKey(proof: SignedRecord, ctx: VisibilityContext): Promise<Holding | null> {
  const definition = ctx.holderTypes.get(proof.type)
  if (definition === undefined) {
    return null
  }
  const op = await verifySignedRecord(proof, ctx.opKind, ctx.methods)
  if (op === null || op.claim.deleted || !recordPayloadMatches(proof, op.claim)) {
    return null
  }
  const { keyID, keyVersion, recipient } = op.claim.meta
  if (
    typeof keyID !== 'string' ||
    !isKeyVersion(keyVersion) ||
    !namesDID(recipient, ctx.requester.peerDID)
  ) {
    return null
  }
  // A wrapping older than the responder's key, as a revoked recipient's is, earns nothing.
  // The key is the proof owner's, which `visibleTo` binds to the guarded record's owner.
  const current = await ctx.currentKeyVersion(normalizeDID(op.claim.owner), keyID)
  if (current === null || keyVersion < current) {
    return null
  }
  // A proof is weighed against the row the responder holds for the same record, so a
  // revoked, superseded or taken-over wrapping cannot stand in for the live one.
  const storedDecision = await ctx.store.get({
    type: proof.type,
    owner: op.claim.owner,
    id: proof.id,
  })
  const storedRecord = storedDecision?.copies[0] ?? null
  const storedOp =
    storedRecord === null ? null : await verifySignedRecord(storedRecord, ctx.opKind, ctx.methods)
  if (!storedRowAdmits(op, storedOp, definition)) {
    return null
  }
  // A proof the responder cannot check for lack of a dependency earns nothing, the same as
  // one that fails, rather than parking as it would in apply.
  for (const dependency of definition.dependencies(proof, op)) {
    if (await isDependencyUnsatisfied(dependency, ctx.store, ctx.opKind, ctx.methods)) {
      return null
    }
  }
  const authorized = await ctx.authorizeProof(proof, storedOp === null ? null : storedRecord)
  return authorized ? { keyID, owner: op.claim.owner } : null
}

/**
 * Whether a record shows that the requester holds a live wrapping of its key: it is of one of
 * `ctx.holderTypes`, its op verifies over the record, its payload matches the signed digest,
 * it is not a tombstone, its `meta.recipient` is the requester's peer DID, its
 * `meta.keyVersion` is at least the responder's current version of `meta.keyID`, the
 * responder's stored row for the same record (if any) is a live op of the same owner that the
 * proof does not lose a merge to, its type's dependencies are satisfied in the responder's
 * store, and `ctx.authorizeProof` accepts it given that stored row.
 *
 * This does not bind the proof to any guarded record's owner; `visibleTo` does, since a proof
 * is valid for its own owner's key alone.
 *
 * Never throws: a proof is hostile input, and one that cannot be checked earns nothing. The
 * proof is only read, never stored or forwarded.
 */
export async function verifyHolderProof(
  proof: SignedRecord,
  ctx: VisibilityContext,
): Promise<boolean> {
  return (await checkedHolding(proof, ctx)) !== null
}

async function checkedHolding(
  proof: SignedRecord,
  ctx: VisibilityContext,
): Promise<Holding | null> {
  try {
    return await heldKey(proof, ctx)
  } catch {
    return null
  }
}

async function isKeyHolder(claim: RecordClaim, ctx: VisibilityContext): Promise<boolean> {
  const { keyID, keyVersion } = claim.meta
  if (
    typeof keyID !== 'string' ||
    (keyVersion !== undefined && !isKeyVersion(keyVersion)) ||
    ctx.holderTypes.size === 0
  ) {
    return false
  }
  const holdings = await ctx.store.list([...ctx.holderTypes.keys()])
  for (const record of [...holdings.flatMap((decision) => decision.copies), ...ctx.proofs]) {
    const holding = await checkedHolding(record, ctx)
    // A key id names a key only within its owner: anyone may sign a wrapping of their own
    // key-1, and it proves nothing about another owner's.
    if (holding !== null && holding.keyID === keyID && holding.owner === claim.owner) {
      return true
    }
  }
  return false
}

async function isShareTarget(claim: RecordClaim, ctx: VisibilityContext): Promise<boolean> {
  const { peerDID, controllerDID } = ctx.requester
  if (
    stringsIn(claim.meta.sharedWith).some(
      (did) => namesDID(did, peerDID) || namesDID(did, controllerDID),
    )
  ) {
    return true
  }
  const members = [normalizedOrNull(peerDID), normalizedOrNull(controllerDID)].filter(
    (did): did is string => did !== null,
  )
  for (const groupID of stringsIn(claim.meta.sharedWithGroups)) {
    for (const did of members) {
      if (await ctx.isGroupMember(groupID, did)) {
        return true
      }
    }
  }
  return false
}

async function satisfiesRule(
  rule: VisibilityRule,
  claim: RecordClaim,
  ctx: VisibilityContext,
): Promise<boolean> {
  switch (rule) {
    case 'ownerDevices':
      return (
        namesDID(claim.owner, ctx.requester.peerDID) ||
        namesDID(claim.owner, ctx.requester.controllerDID)
      )
    case 'recipient':
      return namesDID(claim.meta.recipient, ctx.requester.peerDID)
    case 'keyHolder':
      return await isKeyHolder(claim, ctx)
    case 'sharedWith':
      return await isShareTarget(claim, ctx)
    default:
      return false
  }
}

/**
 * Whether the responder may send a record to the requester: its op verifies over the record,
 * and it satisfies at least one of `rules`. No rules, no one.
 *
 * This minimizes what a requester learns about records it may not have — which keys,
 * co-recipients or share targets exist. It is not the security boundary: encryption protects
 * payloads, and a receiver re-checks every record it applies.
 *
 * Errors from the store or the context's resolvers propagate; errors from a proof do not.
 */
export async function visibleTo(
  record: SignedRecord,
  rules: ReadonlyArray<VisibilityRule>,
  ctx: VisibilityContext,
): Promise<boolean> {
  if (rules.length === 0) {
    return false
  }
  const op = await verifySignedRecord(record, ctx.opKind, ctx.methods)
  if (op === null) {
    return false
  }
  for (const rule of rules) {
    if (await satisfiesRule(rule, op.claim, ctx)) {
      return true
    }
  }
  return false
}

/** A `RecordTypeDefinition.visibleTo` hook that admits a requester any of `rules` admits. */
export function visibilityRules(
  rules: ReadonlyArray<VisibilityRule>,
): (record: SignedRecord, ctx: VisibilityContext) => Promise<boolean> {
  const fixed = [...rules]
  return async (record, ctx) => await visibleTo(record, fixed, ctx)
}

/**
 * The records a responder may send the requester, in their input order: each must be of a
 * registered type whose `visibleTo` hook admits it. A type without the hook is sent to no one.
 *
 * A responder runs this over its records before it fingerprints, splits or lists a range and
 * before it answers a fetch, so a hidden record changes none of them.
 */
export async function filterVisibleRecords(
  records: ReadonlyArray<SignedRecord>,
  types: ReadonlyMap<string, RecordTypeDefinition>,
  ctx: VisibilityContext,
): Promise<Array<SignedRecord>> {
  const visible: Array<SignedRecord> = []
  for (const record of records) {
    const hook = types.get(record.type)?.visibleTo
    if (hook !== undefined && (await hook(record, ctx))) {
      visible.push(record)
    }
  }
  return visible
}
