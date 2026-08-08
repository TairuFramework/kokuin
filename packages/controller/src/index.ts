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
  createRotate,
  DID_PREFIX,
  decodeKey,
  didFromInception,
  type EventCommon,
  type EventType,
  encodeKey,
  type InceptionEvent,
  type RotateEvent,
  type SignedEvent,
  verifyInception,
  verifyRotate,
  verifySignatures,
} from './events.js'
export { VERSION_TAG } from './version.js'
