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

export { canonicalBytes, digestOf, verifyDigest } from './canonical.js'
export {
  agreementPath,
  authorityPath,
  deriveKeyMaterial,
  deriveKeyPair,
  recoveryPath,
} from './derivation.js'
export {
  type CreateRotateOptions,
  createInception,
  createReset,
  createRevoke,
  createRotate,
  DID_PREFIX,
  decodeKey,
  didFromInception,
  type EventCommon,
  type EventType,
  encodeKey,
  type InceptionEvent,
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
  type FoldOptions,
  type FoldResult,
  foldLog,
  foldLogAsync,
  type KeyState,
  keyStateAt,
} from './fold.js'
export { type Duplicity, type ResolveResult, resolveBranches } from './supersede.js'
export { VERSION_TAG } from './version.js'
