import { expect, test } from 'vitest'

import type { Crypto } from '../src/Crypto.nitro.js'
import { providerFor } from '../src/provider.js'

type Bridge = Pick<Crypto, 'abiVersion' | 'execute'>

test('rejects native ABI mismatches and propagates worker failures', async () => {
  const execute: Bridge['execute'] = async () => {
    throw new Error('worker failed')
  }
  expect(() => providerFor({ abiVersion: 2, execute })).toThrow('ABI mismatch')
  const provider = providerFor({ abiVersion: 1, execute })
  await expect(provider.blake3(new Uint8Array(), 32)).rejects.toThrow('worker failed')
})

test('rejects missing batch outputs and malformed verification responses', async () => {
  const empty = providerFor({ abiVersion: 1, execute: async () => [] })
  await expect(empty.blake3Batch([new Uint8Array()], 32)).rejects.toThrow('response')
  const malformed = providerFor({
    abiVersion: 1,
    execute: async () => [new Uint8Array([2]).buffer],
  })
  await expect(
    malformed.verify('EdDSA', new Uint8Array(64), new Uint8Array(), new Uint8Array(32)),
  ).rejects.toThrow('response')
})

test('validates every signing item before dispatching any seed', async () => {
  const provider = providerFor({
    abiVersion: 1,
    execute: async () => {
      throw new Error('dispatched')
    },
  })
  await expect(
    provider.signBatch('EdDSA', [
      { privateKey: new Uint8Array(32), message: new Uint8Array() },
      { privateKey: new Uint8Array(31), message: new Uint8Array() },
    ]),
  ).rejects.toThrow(TypeError)
})

test('signing batch membership is fixed before native dispatch', async () => {
  const provider = providerFor({
    abiVersion: 1,
    execute: async () => [new Uint8Array(64).fill(1).buffer, new Uint8Array(64).fill(2).buffer],
  })
  const items = [
    { privateKey: new Uint8Array(32), message: new Uint8Array() },
    { privateKey: new Uint8Array(32), message: new Uint8Array() },
  ]
  const operation = provider.signBatch('EdDSA', items)
  items.length = 0
  expect(await operation).toEqual([new Uint8Array(64).fill(1), new Uint8Array(64).fill(2)])
})

test('verification batch membership ignores later caller additions', async () => {
  const provider = providerFor({
    abiVersion: 1,
    execute: async () => [new Uint8Array([1]).buffer],
  })
  const item = {
    alg: 'EdDSA' as const,
    publicKey: new Uint8Array(32),
    signature: new Uint8Array(64),
    message: new Uint8Array(),
  }
  const items = [item]
  const operation = provider.verifyBatch(items)
  items.push(item)
  expect(await operation).toEqual([true])
})

test('hash batch membership ignores later caller removals', async () => {
  const provider = providerFor({
    abiVersion: 1,
    execute: async () => [new Uint8Array(32).fill(3).buffer],
  })
  const inputs = [new Uint8Array()]
  const operation = provider.blake3Batch(inputs, 32)
  inputs.pop()
  expect(await operation).toEqual([new Uint8Array(32).fill(3)])
})
