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
  decodeKey,
  didFromInception,
  type EventCommon,
  type EventType,
  encodeKey,
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
  REVOKE_NOT_SIGNED_BY_AUDIENCE,
} from './fold.js'
export { createControllerIdentity, createControllerIdentityAsync } from './identity.js'
export {
  type KeyAlgorithm,
  type TaggedKey,
  tryDecodeKey,
} from './keys.js'
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
