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

export { AUDIENCE_REVOKED, DENY_SET_UNAVAILABLE } from './audience.js'
export { audienceConfirmation } from './controller.js'
export {
  assertValidDelegation,
  checkCapability,
  checkDelegationChain,
  createCapability,
  DEFAULT_MAX_DELEGATION_DEPTH,
} from './delegation.js'
export {
  assertMemberRoot,
  DEFAULT_MEMBER_GRANT_LIFETIME,
  MEMBER_GRANT_KEY_MISMATCH,
  MEMBER_GRANT_NO_IAT,
  MEMBER_GRANT_NO_RESOLVER,
  MEMBER_GRANT_NOT_MEMBER,
  MEMBER_GRANT_PAST_LEASE,
  MEMBER_GRANT_TOO_LONG,
} from './member.js'
export { assertValidPattern, hasPartsMatch, hasPermission, isMatch } from './patterns.js'
export type {
  RevocationBackend,
  RevocationClaims,
  RevocationOptions,
  RevocationRecord,
} from './revocation.js'
export {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
  isTokenRevokedError,
  TokenRevokedError,
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
  MemberClaim,
  Permission,
  SignCapabilityPayload,
  VerifyTokenHook,
} from './types.js'
