import { nobleCrypto } from '@kokuin/crypto'
import { expect, test } from 'vitest'

import { cryptoConformance } from '../src/index.js'

test('runs the complete provider contract against strict noble', async () => {
  for (const entry of cryptoConformance(nobleCrypto)) await entry.run()
})

test('rejects a provider which accepts every verification input', async () => {
  const incorrect = {
    ...nobleCrypto,
    verify: async () => true,
    verifyBatch: async (items: Array<unknown>) => items.map(() => true),
  }
  const outcomes = await Promise.allSettled(
    cryptoConformance(incorrect).map((entry) => entry.run()),
  )
  expect(outcomes.some((entry) => entry.status === 'rejected')).toBe(true)
})

test('rejects a provider which returns the wrong hash', async () => {
  const incorrect = {
    ...nobleCrypto,
    blake3: async (_input: Uint8Array, length: number) => new Uint8Array(length),
  }
  const outcomes = await Promise.allSettled(
    cryptoConformance(incorrect).map((entry) => entry.run()),
  )
  expect(outcomes.some((entry) => entry.status === 'rejected')).toBe(true)
})
