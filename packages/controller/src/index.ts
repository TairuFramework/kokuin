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

/**
 * Protocol version tag. Forms the HKDF `info` string for every derived key, so the DID is a
 * function of it — it can never change once a profile exists. Deliberately independent of the
 * package name.
 */
export const VERSION_TAG = 'did:kokuin/v1'

export { canonicalBytes, digestOf, verifyDigest } from './canonical.js'
