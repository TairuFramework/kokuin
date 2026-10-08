import { describe } from 'vitest'

import { delegationStoreCases } from '../../../packages/store-delegation/test/cases.js'
import { backends } from '../src/backends.js'

describe.each(backends())('$name', (b) => {
  delegationStoreCases({
    name: b.name,
    createAdapter: () => b.createAdapter(),
    cleanup: () => b.cleanup(),
  })
})
