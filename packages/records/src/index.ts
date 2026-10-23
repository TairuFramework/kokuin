/**
 * Replicated records: opaque payloads beside signed ops, independent of any transport or
 * table.
 *
 * @module records
 */

export {
  type ApplyRecordChunkParams,
  type ApplyResult,
  applyRecordChunk,
  type RecordAuthorizeContext,
  type RecordConflict,
  RecordContentRefusalError,
  type RecordDependency,
  type RecordReceiveContext,
  type RecordRequester,
  RecordSourceChangedError,
  type RecordTypeDefinition,
  RecordTypeGraphError,
  type VisibilityContext,
} from './apply.js'
export { compareRecordDecisionHLC, parseBoundedHLC, parseCanonicalHLC } from './clock.js'
export {
  type RecordDecision,
  recordDecisionDigest,
  recordDecisionFromVerifiedCopies,
  type VerifiedRecordCopy,
} from './decision.js'
export {
  RecordOpSigningError,
  signRecordOp,
  type VerifiedRecordOp,
  verifyRecordOp,
  verifySignedRecord,
} from './op.js'
export {
  compareRecordOps,
  type EqualVersionDecision,
  type MergeDecision,
  type MergePolicy,
} from './policy.js'
export {
  assertListedLeaf,
  fingerprintRange,
  RANGE_LEAF_THRESHOLD,
  RANGE_SPLIT,
  type RangeBounds,
  type RangeLeaf,
  type RangeLeafList,
  type RangeSummary,
  RecordRangeError,
  rangeContains,
  rangeLeaf,
  rangePosition,
  splitRange,
  summarizeRange,
} from './range.js'
export {
  advanceRecordPull,
  beginRecordPull,
  nextRequesterSteps,
  type RangeAnswer,
  type RecordPullState,
  type RequesterStep,
} from './reconcile.js'
export {
  canonicalRecordClaim,
  isRecordClaim,
  MAX_RECORD_ID_LENGTH,
  type RecordClaim,
  RecordClaimError,
  type RecordKey,
  recordClaimDigest,
  recordPayloadDigest,
  recordPayloadMatches,
  recordSignerKey,
  type SignedRecord,
} from './record.js'
export {
  getRecordDecisions,
  type RecordDecisionMap,
  type RecordLockKey,
  type RecordStoreAdapter,
  recordKeyText,
} from './store.js'
export {
  filterVisibleRecords,
  type VisibilityRule,
  verifyHolderProof,
  visibilityRules,
  visibleTo,
} from './visibility.js'
