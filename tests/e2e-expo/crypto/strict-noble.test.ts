import { corpus } from '@kokuin/crypto-conformance'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { expect, test } from 'vitest'

import { strictNoble } from './strict-noble.js'

const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
const key = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
const signature = hexToBytes(
  'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
)

for (const vector of corpus.verify) {
  test(`matches the shared corpus: ${vector.name}`, async () => {
    expect(
      await strictNoble.verify(
        vector.alg,
        hexToBytes(vector.signature),
        hexToBytes(vector.message),
        hexToBytes(vector.publicKey),
      ),
    ).toBe(vector.valid)
  })
}

test('signs and verifies the RFC 8032 empty-message vector', async () => {
  expect(await strictNoble.sign('EdDSA', seed, new Uint8Array())).toEqual(signature)
  expect(await strictNoble.verify('EdDSA', signature, new Uint8Array(), key)).toBe(true)
  expect(await strictNoble.verify('EdDSA', signature, new Uint8Array([1]), key)).toBe(false)
})

test('rejects identity, torsion and mixed-order public keys', async () => {
  const identity = new Uint8Array(32)
  identity[0] = 1
  const torsion = ed25519.Point.fromBytes(new Uint8Array(32))
  const mixed = ed25519.Point.BASE.add(torsion).toBytes()
  for (const publicKey of [identity, torsion.toBytes(), mixed]) {
    expect(await strictNoble.verify('EdDSA', signature, new Uint8Array(), publicKey)).toBe(false)
  }
})

test('hashes official blake3 empty-input output at several lengths', async () => {
  const expected = hexToBytes(
    'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a',
  )
  for (const length of [16, 32, 64]) {
    expect(await strictNoble.blake3(new Uint8Array(), length)).toEqual(expected.subarray(0, length))
  }
  await expect(strictNoble.blake3(new Uint8Array(), 0)).rejects.toThrow(RangeError)
  await expect(strictNoble.blake3(new Uint8Array(), 65537)).rejects.toThrow(RangeError)
})

test('preserves mixed batch order and rejects malformed signing batches', async () => {
  expect(
    await strictNoble.verifyBatch([
      { alg: 'EdDSA', signature, message: new Uint8Array(), publicKey: key },
      { alg: 'EdDSA', signature: new Uint8Array(), message: new Uint8Array(), publicKey: key },
    ]),
  ).toEqual([true, false])
  await expect(
    strictNoble.signBatch('EdDSA', [
      { privateKey: seed, message: new Uint8Array() },
      { privateKey: new Uint8Array(31), message: new Uint8Array() },
    ]),
  ).rejects.toThrow(TypeError)
})

test('verifies P-256 raw messages and rejects high-S signatures', async () => {
  const privateKey = new Uint8Array(32)
  privateKey[31] = 1
  const publicKey = p256.getPublicKey(privateKey)
  const message = new TextEncoder().encode('kokuin crypto spike')
  const compact = hexToBytes(
    'd8993d42f5ff5aaf214a10145e5f9ad8bd572acd022d87bd4d8bf989319619e1205bca699914f7f3319fd760301ff494ef95a793ed79c534bab8fbdfcdbcbd58',
  )
  expect(await strictNoble.verify('ES256', compact, message, publicKey)).toBe(true)
  const high = hexToBytes(
    'd8993d42f5ff5aaf214a10145e5f9ad8bd572acd022d87bd4d8bf989319619e1dfa4359566eb080dce60289fcfe00b6acd515319b99dd9503900cee32ea667f9',
  )
  expect(await strictNoble.verify('ES256', high, message, publicKey)).toBe(false)
})

test('rejects invalid algorithms even for empty batches and snapshots subarrays', async () => {
  await expect(strictNoble.signBatch('ES256' as 'EdDSA', [])).rejects.toThrow(TypeError)
  const padded = new Uint8Array(40)
  padded.set(seed, 4)
  const signing = strictNoble.sign('EdDSA', padded.subarray(4, 36), new Uint8Array())
  padded.fill(0)
  expect(await signing).toEqual(signature)
  expect(await strictNoble.signBatch('EdDSA', [])).toEqual([])
  expect(await strictNoble.verifyBatch([])).toEqual([])
  expect(await strictNoble.blake3Batch([], 32)).toEqual([])
  await expect(strictNoble.blake3Batch([], 0)).rejects.toThrow(RangeError)
})
