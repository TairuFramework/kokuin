// Runs against the compiled binary. Build it first with `pnpm run build:native`; this suite fails
// rather than silently testing the nodeCrypto fallback when the binary is missing.
import { cryptoConformance, externalConformance } from '@kokuin/crypto-conformance'
import { ed25519 } from '@noble/curves/ed25519.js'
import { expect, test } from 'vitest'

import { createNapiCrypto, SIGN_SYNC_BATCH_ITEMS } from '../src/index.js'

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
  const expected = await provider.sign({
    alg: 'EdDSA',
    privateKey: seed.slice(),
    message: message.slice(),
  })
  const pending = provider.signBatch({ alg: 'EdDSA', items: [{ privateKey: seed, message }] })
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
    const signatures = await provider.signBatch({ alg: 'EdDSA', items })
    expect(signatures).toHaveLength(2000)
  } finally {
    clearInterval(timer)
  }
  // Signing 2000 items takes tens of milliseconds; a blocked loop would record no ticks at all.
  expect(ticks).toBeGreaterThan(0)
})

test('batch results follow their own entries through the parallel-array boundary', async () => {
  const signer = (fill: number) => {
    const privateKey = new Uint8Array(32).fill(fill)
    return { privateKey, publicKey: ed25519.getPublicKey(privateKey) }
  }
  const [a, b] = [signer(1), signer(2)]
  const [first, second] = [new Uint8Array([1]), new Uint8Array([2])]
  const signatures = await provider.signBatch({
    alg: 'EdDSA',
    items: Array.from({ length: SIGN_SYNC_BATCH_ITEMS + 1 }, (_, index) => {
      return index === 0
        ? { privateKey: a.privateKey, message: first }
        : { privateKey: b.privateKey, message: second }
    }),
  })
  expect(signatures[0]).toEqual(ed25519.sign(first, a.privateKey))
  expect(signatures[1]).toEqual(ed25519.sign(second, b.privateKey))

  const good = ed25519.sign(first, a.privateKey)
  const other = ed25519.sign(second, b.privateKey)
  const item = (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => {
    return { alg: 'EdDSA' as const, signature, message, publicKey }
  }
  expect(
    await provider.verifyBatch([
      item(good, first, a.publicKey),
      item(other, first, a.publicKey),
      item(other, second, b.publicKey),
      item(good, second, a.publicKey),
    ]),
  ).toEqual([true, false, true, false])
})
