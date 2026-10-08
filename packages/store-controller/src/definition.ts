import type { StoreDefinition, StoreProvider } from '@hozon/db'

import type { ControllerStoreAPI } from './api.js'
import { createControllerStore } from './api.js'
import { getControllerMigrations } from './migrations.js'
import type { ControllerStoreTables } from './tables.js'

export const CONTROLLER_STORE = 'controller' as const

export const controllerStoreDefinition: StoreDefinition<ControllerStoreTables, ControllerStoreAPI> =
  {
    name: CONTROLLER_STORE,
    migrations: getControllerMigrations,
    createAPI: createControllerStore,
  }

export async function getControllerStore(provider: StoreProvider): Promise<ControllerStoreAPI> {
  return provider.getStore(CONTROLLER_STORE) as Promise<ControllerStoreAPI>
}
