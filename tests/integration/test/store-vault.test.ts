import { describe } from 'vitest'

import { storeVaultCases } from '../../../packages/store-vault/test/cases.js'
import { replicationCases } from '../../../packages/store-vault/test/replication-cases.js'
import { backends } from '../src/backends.js'

describe.each(backends())('$name', (backend) => {
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
