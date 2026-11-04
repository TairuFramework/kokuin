// Runs against the compiled binary. Build it first with `pnpm run build:native`; this suite fails
// rather than silently testing the nodeCrypto fallback when the binary is missing.
import { cryptoConformance, externalConformance } from '@kokuin/crypto-conformance'
import { expect, test } from 'vitest'

import { createNapiCrypto } from '../src/index.js'

const provider = createNapiCrypto()

test('the native binding loads', () => {
  expect(provider.failure).toBeUndefined()
  expect(provider.backend).toBe('napi')
})

test('passes the provider contract', async () => {
  for (const entry of cryptoConformance(provider)) await entry.run()
})

test('passes every pinned upstream vector', { timeout: 120_000 }, async () => {
  for (const entry of externalConformance(provider)) await entry.run()
})

test('batch inputs are copied before the Promise returns', async () => {
  const seed = new Uint8Array(32).fill(9)
  const message = new Uint8Array(64).fill(3)
  const expected = await provider.sign('EdDSA', seed.slice(), message.slice())
  const pending = provider.signBatch('EdDSA', [{ privateKey: seed, message }])
  seed.fill(0)
  message.fill(0)
  expect(await pending).toEqual([expected])
})

test('a large batch leaves the event loop free while it computes', async () => {
  const seed = new Uint8Array(32).fill(5)
  const items = Array.from({ length: 2000 }, (_, index) => {
    return {
      privateKey: seed,
      message: new Uint8Array([index & 255, index >> 8]),
    }
  })
  let ticks = 0
  const timer = setInterval(() => ticks++, 1)
  try {
    const signatures = await provider.signBatch('EdDSA', items)
    expect(signatures).toHaveLength(2000)
  } finally {
    clearInterval(timer)
  }
  // Signing 2000 items takes tens of milliseconds; a blocked loop would record no ticks at all.
  expect(ticks).toBeGreaterThan(0)
})
