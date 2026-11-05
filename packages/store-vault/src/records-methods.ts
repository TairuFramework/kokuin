import type { StoreProvider } from '@hozon/db'
import type { VaultRecordTypeParams } from '@kokuin/vault'

import { vaultDatabases } from './record-context.js'
import type { VaultStoreAPI } from './types.js'

/** Registry used to verify signed record ops and wrappings. */
export type VaultMethods = NonNullable<VaultRecordTypeParams['methods']>

/** Builds a registry whose resolvers read through the given provider, including transactions. */
export type VaultMethodsFor = (provider: StoreProvider) => VaultMethods

export type MethodsParams = {
  methods?: VaultMethods
  methodsFor?: VaultMethodsFor
}

const methodsByFactory = new WeakMap<VaultMethodsFor, WeakMap<VaultStoreAPI, VaultMethods>>()

export function storeMethods(
  store: VaultStoreAPI,
  params: MethodsParams,
): VaultMethods | undefined {
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

export function snapshotMethods(methods?: VaultMethods): VaultMethods | undefined {
  return methods?.map((method) => {
    return {
      ...method,
      resolve: method.resolve.bind(method),
      resolveHistoric: method.resolveHistoric?.bind(method),
      resolveDenySet: method.resolveDenySet?.bind(method),
      resolveAgreementKey: method.resolveAgreementKey?.bind(method),
    }
  })
}
