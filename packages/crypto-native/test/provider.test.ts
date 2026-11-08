import { runInNewContext } from 'node:vm'
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
  await expect(provider.blake3({ input: new Uint8Array(), dkLen: 32 })).rejects.toThrow(
    'worker failed',
  )
})

test('rejects missing batch outputs and malformed verification responses', async () => {
  const empty = providerFor({ abiVersion: 1, execute: async () => [] })
  await expect(empty.blake3Batch({ inputs: [new Uint8Array()], dkLen: 32 })).rejects.toThrow(
    'response',
  )
  const malformed = providerFor({
    abiVersion: 1,
    execute: async () => [new Uint8Array([2]).buffer],
  })
  await expect(
    malformed.verify({
      alg: 'EdDSA',
      signature: new Uint8Array(64),
      message: new Uint8Array(),
      publicKey: new Uint8Array(32),
    }),
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
    provider.signBatch({
      alg: 'EdDSA',
      items: [
        { privateKey: new Uint8Array(32), message: new Uint8Array() },
        { privateKey: new Uint8Array(31), message: new Uint8Array() },
      ],
    }),
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
  const operation = provider.signBatch({ alg: 'EdDSA', items })
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
  const operation = provider.blake3Batch({ inputs, dkLen: 32 })
  inputs.pop()
  expect(await operation).toEqual([new Uint8Array(32).fill(3)])
})

function echoProvider() {
  return providerFor({
    abiVersion: 1,
    execute: async (requests) =>
      requests.map(({ message }) => {
        return new Uint8Array(message.buffer, message.offset, message.length).slice().buffer
      }),
  })
}

test('accepts byte inputs from another realm', async () => {
  const provider = echoProvider()
  const input: Uint8Array = runInNewContext('new Uint8Array([1, 2, 3])')
  expect(input instanceof Uint8Array).toBe(false)
  expect(await provider.blake3({ input, dkLen: 3 })).toEqual(
    await provider.blake3({ input: new Uint8Array([1, 2, 3]), dkLen: 3 }),
  )
})

test('rejects shared byte inputs from any realm', async () => {
  const provider = echoProvider()
  const foreign: Uint8Array = runInNewContext('new Uint8Array(new SharedArrayBuffer(3))')
  for (const input of [new Uint8Array(new SharedArrayBuffer(3)), foreign]) {
    await expect(provider.blake3({ input, dkLen: 3 })).rejects.toThrow(
      'Expected an unshared Uint8Array',
    )
  }
})
