export type { RevocationClaims } from '@kokuin/capability'

export type { DelegationStoreAPI, PurgeParams } from './api.js'
export {
  createDelegationStore,
  MAX_CAP_TTL_SECONDS,
  MAX_REVOCATION_FUTURE_DRIFT_SECONDS,
  REVOCATION_GC_VERIFIED_GRACE_SECONDS,
} from './api.js'
export {
  DELEGATION_STORE,
  delegationStoreDefinition,
  getDelegationStore,
} from './definition.js'
export {
  createDelegationRevocationBackend,
  createDelegationRevocationChecker,
  VerifiedRevocationError,
} from './revocation-checker.js'
export type {
  DelegationStoreTables,
  DelegationToken,
  DelegationTokenTable,
  HeldRevocation,
  InsertDelegationToken,
  InsertRevokedCapability,
  RevokedCapability,
  RevokedCapabilityTable,
} from './tables.js'
