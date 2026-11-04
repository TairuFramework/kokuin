import { hexToBytes } from '@noble/hashes/utils.js'
import { expect, test } from 'vitest'

import { nobleCrypto } from '../src/index.js'

const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
const signature = hexToBytes(
  'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
)

test('signs the RFC 8032 vector through the public provider', async () => {
  expect(await nobleCrypto.sign('EdDSA', seed, new Uint8Array())).toEqual(signature)
})

test('snapshots offset seed and message views before returning a Promise', async () => {
  const backing = new Uint8Array(40)
  backing.set(seed, 4)
  const operation = nobleCrypto.sign('EdDSA', backing.subarray(4, 36), new Uint8Array())
  backing.fill(0)
  expect(await operation).toEqual(signature)
})

test('rejects shared and detached input buffers', async () => {
  const shared = new Uint8Array(new SharedArrayBuffer(32))
  await expect(nobleCrypto.blake3(shared, 32)).rejects.toThrow(TypeError)
  const detached = new Uint8Array(32)
  structuredClone(detached.buffer, { transfer: [detached.buffer] })
  await expect(nobleCrypto.blake3(detached, 32)).rejects.toThrow(TypeError)
})

test('returns independently owned results for repeated batch inputs', async () => {
  const results = await nobleCrypto.signBatch('EdDSA', [
    { privateKey: seed, message: new Uint8Array() },
    { privateKey: seed, message: new Uint8Array() },
  ])
  results[0]?.fill(0)
  expect(results[1]).toEqual(signature)
  expect(await nobleCrypto.sign('EdDSA', seed, new Uint8Array())).toEqual(signature)
})

test('validates algorithms and lengths even for empty batches', async () => {
  await expect(nobleCrypto.signBatch('ES256' as 'EdDSA', [])).rejects.toThrow(TypeError)
  for (const length of [0, -1, 1.5, 65537, Number.NaN]) {
    await expect(nobleCrypto.blake3Batch([], length)).rejects.toThrow(RangeError)
  }
  expect(await nobleCrypto.blake3Batch([], 65536)).toEqual([])
  expect(await nobleCrypto.verifyBatch([])).toEqual([])
})
