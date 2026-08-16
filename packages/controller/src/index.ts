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
  type CreateRevokeOptions,
  type CreateRotateOptions,
  createInception,
  createReset,
  createRevoke,
  createRevokeWithKey,
  createRotate,
  DID_PREFIX,
  didFromInception,
  type EventCommon,
  type EventType,
  type InceptionEvent,
  KEY_TARGET_PREFIX,
  keyFromTarget,
  keyTarget,
  type RevokeEvent,
  type RotateEvent,
  type SignedEvent,
  verifyInception,
  verifyReset,
  verifyRevoke,
  verifyRotate,
  verifySignatures,
} from './events.js'
export {
  CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD,
  CAPABILITY_REVOKE_NEEDS_VERIFIER,
  CAPABILITY_VERIFIER_FAILED,
  CAPABILITY_VERIFIER_MALFORMED_ANSWER,
  type CapabilityAuthorisation,
  type FoldOptions,
  type FoldResult,
  foldLog,
  foldLogAsync,
  type KeyState,
  keyStateAt,
  MAX_SKIPPED_SLACK,
  pruneDenySet,
  REVOKE_NOT_SIGNED_BY_AUDIENCE,
  TOO_MANY_UNKNOWN_EVENTS,
  type VerifyCapabilityParams,
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
  createControllerIdentityAsync,
  createControllerIdentityWithKey,
  createControllerIdentityWithKeyAsync,
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
export { enumerateProfiles, handleForDID, type ProfileEntry } from './profiles.js'
export { type ControllerResolverOptions, createControllerResolver } from './resolver.js'
export {
  type Duplicity,
  type ResolveFailure,
  type ResolveResult,
  resolveBranches,
  resolveBranchesAsync,
} from './supersede.js'
export { VERSION_TAG } from './version.js'
