export type { CreateVaultStoreParams } from './api.js'
export { createVaultStore } from './api.js'
export { createVaultCoordinator } from './coordinator.js'
export type {
  VaultNotAuthorizedParams,
  VaultSecretUnverifiableParams,
} from './coordinator-context.js'
export {
  VaultKeyLocked,
  VaultNotAuthorized,
  VaultNotFound,
  VaultRepairPending,
  VaultSecretUnverifiable,
  VaultSupersededBranch,
} from './coordinator-context.js'
export type * from './coordinator-types.js'
export type {
  VaultCoordinatorListKeysParams,
  VaultCoordinatorLockAllParams,
} from './coordinator-types.js'
export { getVaultStore, VAULT_STORE, vaultStoreDefinition } from './definition.js'
export { VaultModeConflict, VaultWriteConflict } from './record-context.js'
export type { GetVaultRecordsStoreParams } from './record-definition.js'
export {
  getVaultRecordsStore,
  VAULT_RECORDS_STORE,
  vaultRecordsStoreDefinition,
} from './record-definition.js'
export type * from './record-tables.js'
export type {
  VaultRecords,
  VaultRecordsApplyParams,
  VaultRecordsParams,
  VaultWritePreconditions,
} from './records.js'
export { createVaultRecords, VaultRecordRowError, vaultRecordPortsFor } from './records.js'
export type { VaultMethods, VaultMethodsFor } from './records-methods.js'
export type { VaultRecordRowErrorParams } from './records-rows.js'
export type * from './tables.js'
export type * from './types.js'
