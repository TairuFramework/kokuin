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
