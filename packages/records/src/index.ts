/**
 * Replicated records: opaque payloads beside signed ops, independent of any transport or
 * table.
 *
 * @module records
 */

export type {
  ApplyRecordChunkParamsVerifyCapabilityParams,
  RecordAuthorizeContextVerifyCapabilityParams,
  RecordContentRefusalErrorParams,
  RecordTypeDefinitionAfterApplyParams,
  RecordTypeDefinitionAfterAuthorizeParams,
  RecordTypeDefinitionAuthorizeParams,
  RecordTypeDefinitionDependenciesParams,
  RecordTypeDefinitionLockKeysParams,
  RecordTypeDefinitionOnEqualParams,
  RecordTypeDefinitionPrecheckParams,
  RecordTypeDefinitionVisibleToParams,
  RecordTypeGraphErrorParams,
  VisibilityContextAuthorizeProofParams,
  VisibilityContextCurrentKeyVersionParams,
  VisibilityContextIsGroupMemberParams,
} from './apply.js'
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
export type { CompareRecordDecisionHLCParams, ParseBoundedHLCParams } from './clock.js'
export { compareRecordDecisionHLC, parseBoundedHLC, parseCanonicalHLC } from './clock.js'
export type {
  RecordDecisionDigestParams,
  RecordDecisionFromVerifiedCopiesParams,
} from './decision.js'
export {
  type RecordDecision,
  recordDecisionDigest,
  recordDecisionFromVerifiedCopies,
  type VerifiedRecordCopy,
} from './decision.js'
export type {
  CreateRecordVerifierParams,
  RecordOpSigningErrorParams,
  SignRecordOpParams,
  VerifyRecordOpParams,
  VerifySignedRecordParams,
} from './op.js'
export {
  createRecordVerifier,
  RECORD_OP_MEMO_SIZE,
  RecordOpSigningError,
  signRecordOp,
  type VerifiedRecordOp,
  verifyRecordOp,
  verifySignedRecord,
} from './op.js'
export type { CompareRecordOpsParams, CompareRecordOpsParamsOnEqualParams } from './policy.js'
export {
  compareRecordOps,
  type EqualVersionDecision,
  type MergeDecision,
  type MergePolicy,
} from './policy.js'
export type {
  FingerprintRangeParams,
  RangeContainsParams,
  RangeLeafParams,
  RecordRangeErrorParams,
  SplitRangeParams,
  SummarizeRangeParams,
} from './range.js'
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
export type { AdvanceRecordPullParams, NextRequesterStepsParams } from './reconcile.js'
export {
  advanceRecordPull,
  beginRecordPull,
  nextRequesterSteps,
  type RangeAnswer,
  type RecordPullState,
  type RequesterStep,
} from './reconcile.js'
export type {
  RecordClaimDigestParams,
  RecordClaimErrorParams,
  RecordPayloadDigestParams,
  RecordPayloadMatchesParams,
  RecordSignerKeyParams,
} from './record.js'
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
  snapshotRecord,
} from './record.js'
export type {
  GetRecordDecisionsParams,
  RecordStoreAdapterListByGroupParams,
  RecordStoreAdapterPruneCopyParams,
} from './store.js'
export {
  getRecordDecisions,
  type RecordDecisionMap,
  type RecordLockKey,
  type RecordStoreAdapter,
  recordKeyText,
} from './store.js'
export type {
  FilterVisibleRecordsParams,
  VerifyHolderProofParams,
  VisibleToParams,
} from './visibility.js'
export {
  filterVisibleRecords,
  type VisibilityRule,
  verifyHolderProof,
  visibilityRules,
  visibleTo,
} from './visibility.js'
