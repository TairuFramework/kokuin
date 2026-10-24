import { describe } from 'vitest'

import { storeVaultCases } from '../../../packages/store-vault/test/cases.js'
import { backends } from '../src/backends.js'

describe.each(backends())('$name', (backend) => {
  storeVaultCases({
    name: backend.name,
    createAdapter: () => backend.createAdapter(),
    cleanup: () => backend.cleanup(),
  })
})
