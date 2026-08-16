/**
 * Capability delegation and verification for JWTs.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/capability
 * ```
 *
 * @module capability
 */

// Re-exported so catching the fail-closed throw needs nothing but this package: `@kokuin/token` is a
// plain dependency, not a peer, so a consumer would otherwise add a direct token dependency to name
// the error — the duplication that makes a cross-copy `instanceof` unreliable.
export { isUnresolvableIssuerError, UnresolvableIssuerError } from '@kokuin/token'

export type {
  CapabilityAuthorisation,
  ControllerCapabilityVerifier,
  ControllerCapabilityVerifierParams,
} from './controller.js'
export {
  assertRevokeCapabilityAudience,
  audienceConfirmation,
  createControllerCapabilityVerifier,
  REVOKE_AUDIENCE_KEY_MISMATCH,
  REVOKE_LIFETIME_TOO_LONG,
  REVOKE_NO_AUDIENCE_KEY,
  REVOKE_NO_POSITION,
  REVOKE_NOT_AUTHORISED,
  REVOKE_UNBOUNDED_LIFETIME,
} from './controller.js'
export {
  AUDIENCE_REVOKED,
  assertValidDelegation,
  checkCapability,
  checkDelegationChain,
  createCapability,
  DEFAULT_MAX_DELEGATION_DEPTH,
  DENY_SET_UNAVAILABLE,
} from './delegation.js'
export { assertValidPattern, hasPartsMatch, hasPermission, isMatch } from './patterns.js'
export type { RevocationBackend, RevocationOptions, RevocationRecord } from './revocation.js'
export {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
} from './revocation.js'
export {
  assertDeviceCapabilityPolicy,
  assertNonExpired,
  assertValidIssuedAt,
  assertValidNotBefore,
  DEFAULT_MAX_DEVICE_LIFETIME_SECONDS,
  type DeviceCapabilityPolicyOptions,
  now,
} from './time.js'
export { assertCapabilityToken, isCapabilityToken } from './token.js'
export type {
  CapabilityPayload,
  CapabilityToken,
  ConfirmationClaim,
  CreateCapabilityOptions,
  DelegationChainOptions,
  Permission,
  SignCapabilityPayload,
  VerifyTokenHook,
} from './types.js'
