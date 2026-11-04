import { nobleCrypto } from '@kokuin/crypto'
import { cryptoConformance } from '@kokuin/crypto-conformance'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { blake3 } from '@noble/hashes/blake3.js'
import { expect, test } from 'vitest'

import { createNapiCrypto, NAPI_ABI_VERSION, type NapiBinding, napiTarget } from '../src/index.js'

// A stand-in binding that records calls and answers with strict noble, so routing and
// validation can be checked without a compiled binary.
function recordingBinding() {
  const calls: Array<string> = []
  const binding: NapiBinding = {
    ABI_VERSION: NAPI_ABI_VERSION,
    sign(seed, message) {
      calls.push('sign')
      return noble.sign(seed, message)
    },
    verify(es256, signature, message, publicKey) {
      calls.push(`verify:${es256 ? 'ES256' : 'EdDSA'}`)
      return noble.verify(es256 ? 'ES256' : 'EdDSA', signature, message, publicKey)
    },
    blake3(input, length) {
      calls.push('blake3')
      return noble.blake3(input, length)
    },
    async signBatch(seeds, messages) {
      calls.push(`signBatch:${seeds.length}`)
      return seeds.map((seed, index) => noble.sign(seed, messages[index] as Uint8Array))
    },
    async verifyBatch(es256, signatures, messages, publicKeys) {
      calls.push(`verifyBatch:${es256.length}`)
      return es256.map((flag, index) =>
        noble.verify(
          flag ? 'ES256' : 'EdDSA',
          signatures[index] as Uint8Array,
          messages[index] as Uint8Array,
          publicKeys[index] as Uint8Array,
        ),
      )
    },
    async blake3Batch(inputs, length) {
      calls.push(`blake3Batch:${inputs.length}`)
      return inputs.map((input) => noble.blake3(input, length))
    },
  }
  return { binding, calls }
}

// Synchronous noble, so the fake binding stays synchronous where the real one is.
const noble = {
  sign: (seed: Uint8Array, message: Uint8Array) => ed25519.sign(message, seed),
  verify(alg: 'EdDSA' | 'ES256', signature: Uint8Array, message: Uint8Array, key: Uint8Array) {
    try {
      return alg === 'EdDSA'
        ? ed25519.verify(signature, message, key, { zip215: false })
        : p256.verify(signature, message, key, { lowS: true, prehash: true, format: 'compact' })
    } catch {
      return false
    }
  },
  blake3: (input: Uint8Array, length: number) => blake3(input, { dkLen: length }),
}

const seed = new Uint8Array(32).fill(7)
const message = new Uint8Array([1, 2, 3])

test('without a binding the provider is nodeCrypto and passes the contract', async () => {
  const provider = createNapiCrypto({ binding: null })
  expect(provider.backend).toBe('node')
  for (const entry of cryptoConformance(provider)) await entry.run()
})

test('a fallback created by loading reports why the binding did not load', () => {
  const provider = createNapiCrypto()
  if (provider.backend === 'node') {
    expect(provider.failure?.reason).toMatch(/^(missing|abi|load)$/)
    expect(provider.failure?.path).toContain(`kokuin-crypto-napi.${napiTarget()}.node`)
  } else {
    expect(provider.failure).toBeUndefined()
  }
})

test('single Ed25519 and blake3 calls run natively and synchronously', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  expect(provider.backend).toBe('napi')
  const signing = provider.sign('EdDSA', seed, message)
  expect(calls).toEqual(['sign'])
  const signature = await signing
  const publicKey = ed25519.getPublicKey(seed)
  expect(await provider.verify('EdDSA', signature, message, publicKey)).toBe(true)
  await provider.blake3(message, 32)
  expect(calls).toEqual(['sign', 'verify:EdDSA', 'blake3'])
})

test('single ES256 verification stays on nodeCrypto', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  const secret = p256.utils.randomSecretKey()
  const signature = p256.sign(message, secret, { lowS: true, prehash: true, format: 'compact' })
  const publicKey = p256.getPublicKey(secret, true)
  expect(await provider.verify('ES256', signature, message, publicKey)).toBe(true)
  expect(calls).toEqual([])
})

test('batches go to the native batch methods, and empty batches never reach them', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  const [signature] = await provider.signBatch('EdDSA', [{ privateKey: seed, message }])
  const publicKey = ed25519.getPublicKey(seed)
  expect(
    await provider.verifyBatch([
      { alg: 'EdDSA', signature: signature as Uint8Array, message, publicKey },
    ]),
  ).toEqual([true])
  await provider.blake3Batch([message, message], 16)
  expect(await provider.signBatch('EdDSA', [])).toEqual([])
  expect(await provider.verifyBatch([])).toEqual([])
  expect(await provider.blake3Batch([], 16)).toEqual([])
  expect(calls).toEqual(['signBatch:1', 'verifyBatch:1', 'blake3Batch:2'])
})

test('invalid arguments reject like noble without reaching the binding', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  const shared = new Uint8Array(new SharedArrayBuffer(32))
  const cases: Array<[Promise<unknown>, Promise<unknown>]> = [
    [
      provider.sign('EdDSA', new Uint8Array(31), message),
      nobleCrypto.sign('EdDSA', new Uint8Array(31), message),
    ],
    [
      provider.sign('ES256' as 'EdDSA', seed, message),
      nobleCrypto.sign('ES256' as 'EdDSA', seed, message),
    ],
    [
      provider.verify('RS256' as 'EdDSA', seed, message, seed),
      nobleCrypto.verify('RS256' as 'EdDSA', seed, message, seed),
    ],
    [
      provider.verify('EdDSA', shared, message, seed),
      nobleCrypto.verify('EdDSA', shared, message, seed),
    ],
    [provider.blake3(message, 0), nobleCrypto.blake3(message, 0)],
    [provider.blake3(shared, 32), nobleCrypto.blake3(shared, 32)],
    [
      provider.signBatch('EdDSA', [{ privateKey: new Uint8Array(8), message }]),
      nobleCrypto.signBatch('EdDSA', [{ privateKey: new Uint8Array(8), message }]),
    ],
    [
      provider.verifyBatch([
        { alg: 'RS256' as 'EdDSA', signature: seed, message, publicKey: seed },
      ]),
      nobleCrypto.verifyBatch([
        { alg: 'RS256' as 'EdDSA', signature: seed, message, publicKey: seed },
      ]),
    ],
    [provider.blake3Batch([message], 65537), nobleCrypto.blake3Batch([message], 65537)],
  ]
  for (const [ours, theirs] of cases) {
    const [mine, reference] = await Promise.allSettled([ours, theirs])
    expect(mine?.status).toBe('rejected')
    expect(reference?.status).toBe('rejected')
    const expected = (reference as PromiseRejectedResult).reason.constructor
    expect((mine as PromiseRejectedResult).reason).toBeInstanceOf(expected)
  }
  expect(calls).toEqual([])
})

test('a native failure after construction rejects instead of falling back', async () => {
  const { binding } = recordingBinding()
  const provider = createNapiCrypto({
    binding: {
      ...binding,
      sign() {
        throw new Error('native failure')
      },
    },
  })
  await expect(provider.sign('EdDSA', seed, message)).rejects.toThrow('native failure')
})
