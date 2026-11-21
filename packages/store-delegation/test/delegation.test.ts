import { describe } from 'vitest'

import { delegationStoreCases, type StoreHarness } from './cases.js'

// Reuse the integration backends without extending this package's TypeScript root.
const harnessURL = new URL('../../../tests/integration/src/backends.ts', import.meta.url).href
const { backends } = (await import(harnessURL)) as { backends(): Array<StoreHarness> }

describe.each(backends())('delegation store ($name)', (backend) => {
  delegationStoreCases(backend)
})
