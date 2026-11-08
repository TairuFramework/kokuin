import { runInNewContext } from 'node:vm'
import { nobleCrypto } from '@kokuin/crypto'
import { cryptoConformance } from '@kokuin/crypto-conformance'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { blake3 } from '@noble/hashes/blake3.js'
import { expect, test } from 'vitest'

import {
  BLAKE3_SYNC_BATCH_BYTES,
  createNapiCrypto,
  NAPI_ABI_VERSION,
  type NapiBinding,
  napiTarget,
  SIGN_SYNC_BATCH_ITEMS,
} from '../src/index.js'

type NapiVerifyParams = {
  es256: boolean
  signature: Uint8Array<ArrayBufferLike>
  message: Uint8Array<ArrayBufferLike>
  publicKey: Uint8Array<ArrayBufferLike>
}
type VerifyParams = {
  alg: 'EdDSA' | 'ES256'
  signature: Uint8Array
  message: Uint8Array
  key: Uint8Array
}

// A stand-in binding that records calls and answers with strict noble, so routing and
// validation can be checked without a compiled binary.
function recordingBinding() {
  const calls: Array<string> = []
  const binding: NapiBinding = {
    ABI_VERSION: NAPI_ABI_VERSION,
    sign({ seed, message }) {
      calls.push('sign')
      return noble.sign(seed, message)
    },
    verify({ es256, signature, message, publicKey }: NapiVerifyParams) {
      calls.push(`verify:${es256 ? 'ES256' : 'EdDSA'}`)
      return noble.verify({
        alg: es256 ? 'ES256' : 'EdDSA',
        signature,
        message,
        key: publicKey,
      })
    },
    blake3({ input, length }) {
      calls.push('blake3')
      return noble.blake3(input, length)
    },
    async signBatch(items) {
      calls.push(`signBatch:${items.length}`)
      return items.map((item) => noble.sign(item.seed, item.message))
    },
    async verifyBatch(items: Array<NapiVerifyParams>) {
      calls.push(`verifyBatch:${items.length}`)
      return items.map((item) => {
        return noble.verify({
          alg: item.es256 ? 'ES256' : 'EdDSA',
          signature: item.signature,
          message: item.message,
          key: item.publicKey,
        })
      })
    },
    async blake3Batch({ inputs, length }) {
      calls.push(`blake3Batch:${inputs.length}`)
      return inputs.map((input) => noble.blake3(input, length))
    },
  }
  return { binding, calls }
}

// Synchronous noble, so the fake binding stays synchronous where the real one is.
const noble = {
  sign: (seed: Uint8Array, message: Uint8Array) => ed25519.sign(message, seed),
  verify({ alg, signature, message, key }: VerifyParams) {
    // The same strict checks as nobleCrypto: canonical, prime-order A and R, cofactorless.
    const strictPoint = (bytes: Uint8Array) => {
      const point = ed25519.Point.fromBytes(bytes, false)
      return !point.isSmallOrder() && point.isTorsionFree()
    }
    try {
      return alg === 'EdDSA'
        ? key.length === 32 &&
            signature.length === 64 &&
            strictPoint(key) &&
            strictPoint(signature.subarray(0, 32)) &&
            ed25519.verify(signature, message, key, { zip215: false })
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

test('the native routes pass the contract, with a stand-in binding', async () => {
  const { binding } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  expect(provider.backend).toBe('napi')
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
  const signing = provider.sign({ alg: 'EdDSA', privateKey: seed, message })
  expect(calls).toEqual(['sign'])
  const signature = await signing
  const publicKey = ed25519.getPublicKey(seed)
  expect(
    await provider.verify({
      alg: 'EdDSA',
      signature,
      message,
      publicKey,
    }),
  ).toBe(true)
  await provider.blake3({ input: message, dkLen: 32 })
  expect(calls).toEqual(['sign', 'verify:EdDSA', 'blake3'])
})

test('single ES256 verification stays on nodeCrypto', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  const secret = p256.utils.randomSecretKey()
  const signature = p256.sign(message, secret, { lowS: true, prehash: true, format: 'compact' })
  const publicKey = p256.getPublicKey(secret, true)
  expect(
    await provider.verify({
      alg: 'ES256',
      signature,
      message,
      publicKey,
    }),
  ).toBe(true)
  expect(calls).toEqual([])
})

test('verify batches of two or more and large sign batches use the pool; smaller ones stay on the calling thread', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  const [signature] = await provider.signBatch({
    alg: 'EdDSA',
    items: [{ privateKey: seed, message }],
  })
  const publicKey = ed25519.getPublicKey(seed)
  expect(
    await provider.verifyBatch([
      { alg: 'EdDSA', signature: signature as Uint8Array, message, publicKey },
    ]),
  ).toEqual([true])
  expect(await provider.signBatch({ alg: 'EdDSA', items: [] })).toEqual([])
  expect(await provider.verifyBatch([])).toEqual([])
  expect(await provider.blake3Batch({ inputs: [], dkLen: 16 })).toEqual([])
  expect(calls).toEqual(['sign', 'verify:EdDSA'])
  calls.length = 0
  const pair = [
    { privateKey: seed, message },
    { privateKey: seed, message },
  ]
  const [first, second] = await provider.signBatch({ alg: 'EdDSA', items: pair })
  expect(first).toEqual(signature)
  await provider.verifyBatch([
    { alg: 'EdDSA', signature: first as Uint8Array, message, publicKey },
    { alg: 'EdDSA', signature: second as Uint8Array, message, publicKey },
  ])
  expect(calls).toEqual(['sign', 'sign', 'verifyBatch:2'])
  calls.length = 0
  const many = Array.from({ length: SIGN_SYNC_BATCH_ITEMS + 1 }, () => {
    return {
      privateKey: seed,
      message,
    }
  })
  await provider.signBatch({ alg: 'EdDSA', items: many })
  expect(calls).toEqual([`signBatch:${SIGN_SYNC_BATCH_ITEMS + 1}`])
})

test('mixed verification batches send only Ed25519 items to native and keep their order', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  const edKey = ed25519.getPublicKey(seed)
  const edSignature = ed25519.sign(message, seed)
  const secret = p256.utils.randomSecretKey()
  const esKey = p256.getPublicKey(secret, true)
  const esSignature = p256.sign(message, secret, { lowS: true, prehash: true, format: 'compact' })
  const wrong = Uint8Array.of(9)
  const results = await provider.verifyBatch([
    { alg: 'ES256', signature: esSignature, message, publicKey: esKey },
    { alg: 'EdDSA', signature: edSignature, message: wrong, publicKey: edKey },
    { alg: 'ES256', signature: esSignature, message: wrong, publicKey: esKey },
    { alg: 'EdDSA', signature: edSignature, message, publicKey: edKey },
  ])
  expect(results).toEqual([true, false, false, true])
  expect(calls).toEqual(['verifyBatch:2'])
  calls.length = 0
  expect(
    await provider.verifyBatch([
      { alg: 'ES256', signature: esSignature, message, publicKey: esKey },
    ]),
  ).toEqual([true])
  expect(calls).toEqual([])
})

test('blake3 batches hash on the calling thread up to the threshold, then on the pool', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  const half = new Uint8Array(BLAKE3_SYNC_BATCH_BYTES / 2)
  const small = provider.blake3Batch({ inputs: [half, half], dkLen: 16 })
  expect(calls).toEqual(['blake3', 'blake3'])
  expect((await small).map((hash) => hash.length)).toEqual([16, 16])
  calls.length = 0
  await provider.blake3Batch({ inputs: [half, half, Uint8Array.of(1)], dkLen: 16 })
  expect(calls).toEqual(['blake3Batch:3'])
})

test('invalid arguments reject like noble without reaching the binding', async () => {
  const { binding, calls } = recordingBinding()
  const provider = createNapiCrypto({ binding })
  const shared = new Uint8Array(new SharedArrayBuffer(32))
  const cases: Array<[Promise<unknown>, Promise<unknown>]> = [
    [
      provider.sign({ alg: 'EdDSA', privateKey: new Uint8Array(31), message }),
      nobleCrypto.sign({ alg: 'EdDSA', privateKey: new Uint8Array(31), message }),
    ],
    [
      provider.sign({ alg: 'ES256' as 'EdDSA', privateKey: seed, message }),
      nobleCrypto.sign({ alg: 'ES256' as 'EdDSA', privateKey: seed, message }),
    ],
    [
      provider.verify({
        alg: 'RS256' as 'EdDSA',
        signature: seed,
        message,
        publicKey: seed,
      }),
      nobleCrypto.verify({
        alg: 'RS256' as 'EdDSA',
        signature: seed,
        message,
        publicKey: seed,
      }),
    ],
    [
      provider.verify({ alg: 'EdDSA', signature: shared, message, publicKey: seed }),
      nobleCrypto.verify({ alg: 'EdDSA', signature: shared, message, publicKey: seed }),
    ],
    [
      provider.blake3({ input: message, dkLen: 0 }),
      nobleCrypto.blake3({ input: message, dkLen: 0 }),
    ],
    [
      provider.blake3({ input: shared, dkLen: 32 }),
      nobleCrypto.blake3({ input: shared, dkLen: 32 }),
    ],
    [
      provider.signBatch({ alg: 'EdDSA', items: [{ privateKey: new Uint8Array(8), message }] }),
      nobleCrypto.signBatch({ alg: 'EdDSA', items: [{ privateKey: new Uint8Array(8), message }] }),
    ],
    [
      provider.verifyBatch([
        { alg: 'RS256' as 'EdDSA', signature: seed, message, publicKey: seed },
      ]),
      nobleCrypto.verifyBatch([
        { alg: 'RS256' as 'EdDSA', signature: seed, message, publicKey: seed },
      ]),
    ],
    [
      provider.blake3Batch({ inputs: [message], dkLen: 65537 }),
      nobleCrypto.blake3Batch({ inputs: [message], dkLen: 65537 }),
    ],
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
  await expect(provider.sign({ alg: 'EdDSA', privateKey: seed, message })).rejects.toThrow(
    'native failure',
  )
})

test('a binding that answers a batch short rejects instead of leaving entries undefined', async () => {
  const { binding } = recordingBinding()
  const provider = createNapiCrypto({
    binding: {
      ...binding,
      signBatch: async () => [],
      verifyBatch: async () => [true],
      blake3Batch: async () => [],
    },
  })
  const seed = new Uint8Array(32).fill(1)
  const message = new Uint8Array(1)
  const publicKey = ed25519.getPublicKey(seed)
  const signature = ed25519.sign(message, seed)
  const item = { alg: 'EdDSA' as const, signature, message, publicKey }
  const count = 'Invalid native crypto response count'

  await expect(
    provider.signBatch({
      alg: 'EdDSA',
      items: Array.from({ length: SIGN_SYNC_BATCH_ITEMS + 1 }, () => ({
        privateKey: seed,
        message,
      })),
    }),
  ).rejects.toThrow(count)
  await expect(provider.verifyBatch([item, item])).rejects.toThrow(count)
  await expect(
    provider.blake3Batch({ inputs: [new Uint8Array(BLAKE3_SYNC_BATCH_BYTES + 1)], dkLen: 32 }),
  ).rejects.toThrow(count)
})

test('accepts byte inputs from another realm', async () => {
  const provider = createNapiCrypto({ binding: recordingBinding().binding })
  const input: Uint8Array = runInNewContext('new Uint8Array([1, 2, 3])')
  expect(input instanceof Uint8Array).toBe(false)
  const local = new Uint8Array([1, 2, 3])
  expect(await provider.blake3({ input, dkLen: 32 })).toEqual(
    await provider.blake3({ input: local, dkLen: 32 }),
  )
})

test('rejects shared byte inputs from any realm', async () => {
  const provider = createNapiCrypto({ binding: recordingBinding().binding })
  const foreign: Uint8Array = runInNewContext('new Uint8Array(new SharedArrayBuffer(3))')
  for (const input of [new Uint8Array(new SharedArrayBuffer(3)), foreign]) {
    await expect(provider.blake3({ input, dkLen: 32 })).rejects.toThrow(
      'Expected an unshared Uint8Array',
    )
  }
})
