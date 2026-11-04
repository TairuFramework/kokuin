import { type CryptoProvider, nobleCrypto, type VerifyItem } from '@kokuin/crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { maybeYield } from '@sozai/async'
import { beforeEach, expect, test, vi } from 'vitest'

import { clearVerifiedSignatureMemo, verifiedSignatureMemoSize } from '../src/verified-memo.js'
import { getVerifier } from '../src/verifier.js'

vi.mock('@sozai/async', () => ({ maybeYield: vi.fn(async () => {}) }))

function fixture(alg: VerifyItem['alg'], value = 1): VerifyItem {
  const seed = new Uint8Array(32).fill(value)
  const message = new Uint8Array([value])
  return alg === 'EdDSA'
    ? {
        alg,
        message,
        signature: ed25519.sign(message, seed),
        publicKey: ed25519.getPublicKey(seed),
      }
    : {
        alg,
        message,
        signature: p256.sign(message, seed, { prehash: true, lowS: true }),
        publicKey: p256.getPublicKey(seed),
      }
}

function provider(overrides: Partial<CryptoProvider> = {}) {
  const singles = vi.fn(nobleCrypto.verify)
  const batches = vi.fn(nobleCrypto.verifyBatch)
  const crypto: CryptoProvider = {
    ...nobleCrypto,
    verify: singles,
    verifyBatch: batches,
    ...overrides,
  }
  return { crypto, singles, batches }
}

function verify(crypto: CryptoProvider, item: VerifyItem) {
  return getVerifier(item.alg, undefined, { crypto })(item.signature, item.message, item.publicKey)
}

beforeEach(() => {
  clearVerifiedSignatureMemo()
  vi.mocked(maybeYield)
    .mockReset()
    .mockImplementation(async () => {})
})

test('mixed algorithms and validities receive their individual verification results', async () => {
  const p = provider()
  const items = [fixture('EdDSA'), fixture('ES256'), fixture('EdDSA', 2), fixture('ES256', 2)]
  items[1]?.message.fill(9)
  items[2]?.signature.fill(0)
  const expected = await Promise.all(
    items.map((item) => {
      return nobleCrypto.verify({
        alg: item.alg,
        signature: item.signature,
        message: item.message,
        publicKey: item.publicKey,
      })
    }),
  )
  expect(expected).toEqual([true, false, false, true])
  expect(await Promise.all(items.map((item) => verify(p.crypto, item)))).toEqual(expected)
  expect(p.batches).toHaveBeenCalledExactlyOnceWith(items)
  expect(p.singles).not.toHaveBeenCalled()
  expect(verifiedSignatureMemoSize()).toBe(2)
  await Promise.all(items.map((item) => verify(p.crypto, item)))
  expect(p.batches).toHaveBeenCalledTimes(2)
  expect(p.batches.mock.calls[1]?.[0]).toEqual([items[1], items[2]])
})

test('success memo stays per provider and algorithm and hits skip provider operations', async () => {
  const p = provider({
    verify: vi.fn(async () => true),
    verifyBatch: vi.fn(async (items) => items.map(() => true)),
  })
  const item = fixture('EdDSA')
  expect(await verify(p.crypto, item)).toBe(true)
  expect(verify(p.crypto, item)).toBe(true)
  expect(p.crypto.verify).toHaveBeenCalledTimes(1)
  expect(getVerifier('EdDSA', undefined, p)).toBe(getVerifier('EdDSA', undefined, p))
  expect(await verify(p.crypto, { ...item, alg: 'ES256' })).toBe(true)
  expect(p.crypto.verify).toHaveBeenCalledTimes(2)
  const other = provider({ verify: vi.fn(async () => false) })
  expect(await verify(other.crypto, item)).toBe(false)
  expect(await verify(other.crypto, item)).toBe(false)
  expect(other.crypto.verify).toHaveBeenCalledTimes(2)
  expect(p.crypto.verifyBatch).not.toHaveBeenCalled()
  expect(verifiedSignatureMemoSize()).toBe(2)
})

test('custom verifiers bypass memo batching and fairness routing on every call', async () => {
  const p = provider()
  const item = fixture('EdDSA')
  const custom = vi.fn(() => false)
  const verifier = getVerifier('EdDSA', { EdDSA: custom }, p)
  expect(
    await Promise.all([
      verifier(item.signature, item.message, item.publicKey),
      verifier(item.signature, item.message, item.publicKey),
    ]),
  ).toEqual([false, false])
  expect(custom).toHaveBeenCalledTimes(2)
  expect(p.singles).not.toHaveBeenCalled()
  expect(p.batches).not.toHaveBeenCalled()
  expect(maybeYield).not.toHaveBeenCalled()
  expect(verifiedSignatureMemoSize()).toBe(0)
})

test('batch rejection reaches every caller unchanged without caching or fallback', async () => {
  const error = new Error('batch unavailable')
  const batch = vi.fn(async () => {
    throw error
  })
  const p = provider({ verifyBatch: batch })
  const items = [fixture('EdDSA'), fixture('ES256')]
  for (let attempt = 0; attempt < 2; attempt++) {
    const results = await Promise.allSettled(items.map((item) => verify(p.crypto, item)))
    for (const result of results) {
      expect(result.status).toBe('rejected')
      if (result.status === 'rejected') expect(result.reason).toBe(error)
    }
    expect(verifiedSignatureMemoSize()).toBe(0)
  }
  expect(batch).toHaveBeenCalledTimes(2)
  expect(p.singles).not.toHaveBeenCalled()
})

test('queued bytes are owned before fairness or flush suspension', async () => {
  const p = provider()
  const items = [fixture('EdDSA'), fixture('ES256')]
  const originals = structuredClone(items)
  const pending = items.map((item) => verify(p.crypto, item))
  for (const item of items) {
    item.signature.fill(0)
    item.message.fill(0)
    item.publicKey.fill(0)
  }
  expect(await Promise.all(pending)).toEqual([true, true])
  expect(p.batches).toHaveBeenCalledExactlyOnceWith(originals)
  expect(verifiedSignatureMemoSize()).toBe(2)
  expect(originals.map((item) => verify(p.crypto, item))).toEqual([true, true])
})

test('same-turn callers coalesce after every fairness yield including separate macrotasks', async () => {
  const p = provider()
  let yielded = 0
  p.batches.mockImplementation(async (items) => {
    expect(yielded).toBe(3)
    return nobleCrypto.verifyBatch(items)
  })
  vi.mocked(maybeYield).mockImplementation(() => {
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        yielded++
        resolve()
      }, 0)
    })
  })
  const items = [fixture('EdDSA'), fixture('ES256'), fixture('EdDSA', 2)]
  const pending = items.map((item) => verify(p.crypto, item))
  expect(maybeYield).toHaveBeenCalledTimes(3)
  expect(p.singles).not.toHaveBeenCalled()
  expect(p.batches).not.toHaveBeenCalled()
  expect(await Promise.all(pending)).toEqual([true, true, true])
  expect(yielded).toBe(3)
  expect(p.batches).toHaveBeenCalledExactlyOnceWith(items)
  expect(p.singles).not.toHaveBeenCalled()
})

test('a lone macrotask yield cannot split its same-turn group', async () => {
  const p = provider()
  vi.mocked(maybeYield).mockImplementationOnce(
    () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
  )
  const items = [fixture('EdDSA'), fixture('ES256')]
  expect(await Promise.all(items.map((item) => verify(p.crypto, item)))).toEqual([true, true])
  expect(p.batches).toHaveBeenCalledExactlyOnceWith(items)
  expect(p.singles).not.toHaveBeenCalled()
})

test('different providers own separate concurrent batches', async () => {
  const first = provider()
  const second = provider()
  const a = [fixture('EdDSA'), fixture('ES256')]
  const b = [fixture('EdDSA', 2), fixture('ES256', 2)]
  expect(
    await Promise.all([
      ...a.map((item) => verify(first.crypto, item)),
      ...b.map((item) => verify(second.crypto, item)),
    ]),
  ).toEqual([true, true, true, true])
  expect(first.batches).toHaveBeenCalledExactlyOnceWith(a)
  expect(second.batches).toHaveBeenCalledExactlyOnceWith(b)
  expect(first.singles).not.toHaveBeenCalled()
  expect(second.singles).not.toHaveBeenCalled()
})

test('a miss after the flush microtask starts a separate group even while prior yields wait', async () => {
  const p = provider()
  vi.mocked(maybeYield).mockImplementationOnce(
    () => new Promise<void>((resolve) => setTimeout(resolve, 0)),
  )
  const first = verify(p.crypto, fixture('EdDSA'))
  await new Promise<void>((resolve) => queueMicrotask(resolve))
  const second = verify(p.crypto, fixture('ES256'))
  expect(await Promise.all([first, second])).toEqual([true, true])
  expect(p.singles).toHaveBeenCalledTimes(2)
  expect(p.batches).not.toHaveBeenCalled()
})
