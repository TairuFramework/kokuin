import type { StoreProvider } from '@hozon/db'
import type { VaultRecordTypeParams } from '@kokuin/vault'

import { vaultDatabases } from './record-context.js'
import type { VaultStoreAPI } from './types.js'

export type MethodsParams = {
  methods?: VaultRecordTypeParams['methods']
  methodsFor?: (provider: StoreProvider) => NonNullable<VaultRecordTypeParams['methods']>
}

const methodsByFactory = new WeakMap<
  NonNullable<MethodsParams['methodsFor']>,
  WeakMap<VaultStoreAPI, NonNullable<MethodsParams['methods']>>
>()

export function storeMethods(
  store: VaultStoreAPI,
  params: MethodsParams,
): MethodsParams['methods'] {
  if (params.methodsFor === undefined) return params.methods

  let byStore = methodsByFactory.get(params.methodsFor)
  if (byStore === undefined) {
    byStore = new WeakMap()
    methodsByFactory.set(params.methodsFor, byStore)
  }
  let methods = byStore.get(store)
  if (methods === undefined) {
    const database = vaultDatabases.get(store)
    if (database === undefined) throw new TypeError('Methods require a registered vault store')
    methods = params.methodsFor(database.context.provider)
    byStore.set(store, methods)
  }
  return methods
}
