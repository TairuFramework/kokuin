import type { StoreDefinition, StoreProvider } from '@hozon/db'

import type { DelegationStoreAPI } from './api.js'
import { createDelegationStore } from './api.js'
import { getDelegationMigrations } from './migrations.js'
import type { DelegationStoreTables } from './tables.js'

export const DELEGATION_STORE = 'delegation' as const

export const delegationStoreDefinition: StoreDefinition<DelegationStoreTables, DelegationStoreAPI> =
  {
    name: DELEGATION_STORE,
    migrations: getDelegationMigrations,
    createAPI: createDelegationStore,
  }

export async function getDelegationStore(provider: StoreProvider): Promise<DelegationStoreAPI> {
  return provider.getStore(DELEGATION_STORE) as Promise<DelegationStoreAPI>
}
