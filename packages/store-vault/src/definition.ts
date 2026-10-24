import type { StoreDefinition, StoreProvider } from '@hozon/db'

import { createVaultStore } from './api.js'
import { getVaultMigrations } from './migrations.js'
import type { VaultStoreTables } from './tables.js'
import type { VaultStoreAPI } from './types.js'

export const VAULT_STORE = 'vault' as const
export const vaultStoreDefinition: StoreDefinition<VaultStoreTables, VaultStoreAPI> = {
  name: VAULT_STORE,
  dependsOn: [],
  migrations: getVaultMigrations,
  createAPI: createVaultStore,
}
export async function getVaultStore(provider: StoreProvider): Promise<VaultStoreAPI> {
  return provider.getStore(VAULT_STORE) as Promise<VaultStoreAPI>
}
