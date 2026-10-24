import { describe } from 'vitest'

import { storeVaultCases } from '../../../packages/store-vault/test/cases.js'
import { coordinatorCases } from '../../../packages/store-vault/test/coordinator-cases.js'
import { replicationCases } from '../../../packages/store-vault/test/replication-cases.js'
import { backends } from '../src/backends.js'

describe.each(backends())('$name', (backend) => {
  coordinatorCases({
    name: backend.name,
    createAdapter: () => backend.createAdapter(),
    cleanup: () => backend.cleanup(),
  })
  replicationCases({
    name: backend.name,
    createAdapter: () => backend.createAdapter(),
    cleanup: () => backend.cleanup(),
  })
  storeVaultCases({
    name: backend.name,
    createAdapter: () => backend.createAdapter(),
    cleanup: () => backend.cleanup(),
  })
})
