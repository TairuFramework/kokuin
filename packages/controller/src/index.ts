/**
 * did:kokuin controller key event log.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/controller
 * ```
 *
 * @module controller
 */

export {
  canonicalBytes,
  digestOf,
  isCanonicalizable,
  MAX_CANONICAL_DEPTH,
  verifyDigest,
  withinCanonicalDepth,
} from './canonical.js'
export {
  agreementPath,
  authorityPath,
  deriveKeyMaterial,
  deriveKeyPair,
  recoveryPath,
} from './derivation.js'
export {
  type AddEvent,
  type CreateAddParams,
  type CreateRemoveParams,
  type CreateRenewParams,
  type CreateRevokeParams,
  createAdd,
  createRemove,
  createRenew,
  createRevoke,
  type EpochEvent,
  type EpochEventCommon,
  type EpochEventType,
  type EpochSigner,
  isEpochEventShape,
  type RemoveEvent,
  type RenewEvent,
  type RevokeEvent,
  verifyEpochSignature,
} from './epoch-events.js'
export {
  type CreateRotateOptions,
  createInception,
  createReset,
  createRotate,
  DID_PREFIX,
  didFor,
  didFromInception,
  type EventCommon,
  type EventType,
  type InceptionEvent,
  isMemberEntry,
  KEY_TARGET_PREFIX,
  keyFromTarget,
  keyTarget,
  type MemberEntry,
  type RotateEvent,
  type SignedEvent,
  type StateSnapshot,
  verifyInception,
  verifyReset,
  verifyRotate,
  verifySignatures,
} from './events.js'
export {
  type FoldResult,
  foldLog,
  type KeyState,
  keyStateAt,
  MAX_SKIPPED_SLACK,
  type MemberState,
  ROTATE_NEEDS_SNAPSHOT,
  SNAPSHOT_DROPS_RETIRED_KEY,
  SNAPSHOT_MALFORMED,
  SNAPSHOT_MEMBER_DID_MISMATCH,
  SNAPSHOT_MEMBER_KEY_IS_ROOT,
  snapshotOf,
  TOO_MANY_UNKNOWN_EVENTS,
} from './fold.js'
export {
  authoritativeStates,
  createMemoryLogStore,
  LOG_FORKED,
  LOG_NOT_AUTHORITATIVE,
  type LogStore,
} from './history.js'
export {
  createControllerIdentity,
  createControllerIdentityWithKey,
} from './identity.js'
export {
  decodeKey,
  encodeKey,
  type KeyAlgorithm,
  type TaggedKey,
  tryDecodeKey,
} from './keys.js'
export {
  type ProvideControllerIdentityParams,
  provideControllerIdentity,
} from './keystore-identity.js'
export {
  DEFAULT_LEASE_SECONDS,
  MAX_EPOCH_EVENTS,
  MAX_EVENT_BYTES,
  MAX_EVENT_PARENTS,
  MAX_EVENT_SIGNATURES,
  MAX_LOG_EVENTS,
} from './limits.js'
export {
  type ControllerLog,
  isControllerLog,
  LOG_TOO_LARGE,
  MALFORMED_LOG,
} from './log.js'
export { enumerateProfiles, handleForDID, type ProfileEntry } from './profiles.js'
export { type ControllerResolverOptions, createControllerResolver } from './resolver.js'
export {
  type Duplicity,
  type ResolveFailure,
  type ResolveResult,
  resolveBranches,
} from './supersede.js'
export { VERSION_TAG } from './version.js'
