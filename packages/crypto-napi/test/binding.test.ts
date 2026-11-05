import { expect, test, vi } from 'vitest'

import { createNapiCrypto, loadNapiBinding } from '../src/index.js'

// What a CJS bundle does: `import.meta.url` is undefined, so resolving the binary throws.
const unresolvable = new TypeError('The "path" argument must be of type string')
vi.mock('node:url', () => ({
  fileURLToPath: () => {
    throw unresolvable
  },
}))

test('an unresolvable binary path reports a load failure instead of throwing', () => {
  expect(loadNapiBinding()).toEqual({
    binding: null,
    failure: { reason: 'load', cause: unresolvable },
  })
})

test('an unresolvable binary path selects the nodeCrypto fallback', () => {
  const crypto = createNapiCrypto()
  expect(crypto.backend).toBe('node')
  expect(crypto.failure).toEqual({ reason: 'load', cause: unresolvable })
})
