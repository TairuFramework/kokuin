import { vaultYieldCases } from '../../../packages/store-vault/test/yield-cases.js'
import { backendsNamed } from '../src/backends.js'

for (const backend of backendsNamed('postgres')) {
  vaultYieldCases({
    name: backend.name,
    createAdapter: () => backend.createAdapter(),
    cleanup: () => backend.cleanup(),
  })
}
