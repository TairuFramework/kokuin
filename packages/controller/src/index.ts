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
  createInception,
  DID_PREFIX,
  decodeKey,
  didFromInception,
  type EventCommon,
  type EventType,
  encodeKey,
  type InceptionEvent,
  type SignedEvent,
  verifyInception,
  verifySignatures,
} from './events.js'
export { VERSION_TAG } from './version.js'
