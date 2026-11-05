import type { CryptoAlgorithm, CryptoProvider, VerifyItem } from '@kokuin/crypto'
import { nodeCrypto } from '@kokuin/crypto-node'

import { loadNapiBinding, type NapiBinding, type NapiLoadFailure } from './binding.js'

type AssertVerifyingParams = {
  alg: CryptoAlgorithm
  signature: Uint8Array
  message: Uint8Array
  publicKey: Uint8Array
}

export type NapiCrypto = CryptoProvider & {
  /** `napi` when the Rust binding loaded, `node` when the provider fell back to `nodeCrypto`. */
  readonly backend: 'napi' | 'node'
  /** Why the binding did not load, when `backend` is `node`. */
  readonly failure?: NapiLoadFailure
}

export type NapiCryptoOptions = {
  /** Use this binding instead of loading one. `null` forces the `nodeCrypto` fallback. */
  binding?: NapiBinding | null
}

function assertBytes(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) {
    throw new TypeError('Expected an unshared Uint8Array')
  }
  // Throws TypeError on a detached buffer.
  new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
}

function assertSigning(alg: 'EdDSA', seed: Uint8Array, message: Uint8Array): void {
  if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
  assertBytes(seed)
  assertBytes(message)
  if (seed.length !== 32) throw new TypeError('Expected a 32-byte Ed25519 seed')
}

function assertVerifying({ alg, signature, message, publicKey }: AssertVerifyingParams): void {
  if (alg !== 'EdDSA' && alg !== 'ES256') throw new TypeError('Unsupported verification algorithm')
  for (const bytes of [signature, message, publicKey]) assertBytes(bytes)
}

function assertOutputLength(dkLen: number): void {
  if (!Number.isInteger(dkLen) || dkLen < 1 || dkLen > 65536)
    throw new RangeError('Invalid blake3 output length')
}

/**
 * blake3 batches with at most this much input in total hash on the calling thread. Below it the
 * thread-pool hop and input copies cost more than the hashing (1 MiB hashes in about 135 µs on
 * x86_64); above it, the pool keeps a large hash off the event loop.
 */
export const BLAKE3_SYNC_BATCH_BYTES = 1024 * 1024

/**
 * Ed25519 signing batches of at most this many items sign on the calling thread: about 27 µs per
 * signature at 256 B and 61 µs at 12 KiB on x86_64, against a thread-pool hop that measured
 * slower for every batch the gate covers. Larger batches go to the pool.
 */
export const SIGN_SYNC_BATCH_ITEMS = 32

function assertResultCount<TResult>(results: Array<TResult>, count: number): Array<TResult> {
  if (results.length !== count) throw new Error('Invalid native crypto response count')
  return results
}

/**
 * Routes, set by the Node crypto benchmark gate (scripts/bench-crypto-node.mjs):
 * - Ed25519 sign, Ed25519 verify and blake3 single calls run natively on the calling thread.
 * - ES256 verification, single or batched, uses `nodeCrypto`: OpenSSL is about three times
 *   faster than the Rust P-256 verifier.
 * - Ed25519 verify batches of two or more copy their inputs on the calling thread, then run
 *   natively on the libuv pool, keeping about 100 µs per item off the event loop. A one-item
 *   batch runs on the calling thread, where it is faster than the pool hop.
 * - Ed25519 sign batches run natively on the calling thread up to `SIGN_SYNC_BATCH_ITEMS` items
 *   and on the pool above it.
 * - blake3 batches run natively on the calling thread up to `BLAKE3_SYNC_BATCH_BYTES` of input
 *   and on the pool above it.
 *
 * Arguments are validated in JavaScript exactly as `nobleCrypto` validates them, so every
 * backend raises the same error types. Every method consumes its inputs before its Promise
 * returns.
 */
function napiProvider(binding: NapiBinding): CryptoProvider {
  return {
    async sign({ alg, privateKey: seed, message }) {
      assertSigning(alg, seed, message)
      return binding.sign({ seed, message })
    },
    async signBatch({ alg, items }) {
      if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
      for (const item of items) assertSigning(alg, item.privateKey, item.message)
      if (items.length === 0) return []
      // Signing is cheap enough that the pool hop costs more than it saves for ordinary batches,
      // and the calling-thread route still takes half nodeCrypto's main-thread time.
      if (items.length <= SIGN_SYNC_BATCH_ITEMS) {
        return items.map((item) => binding.sign({ seed: item.privateKey, message: item.message }))
      }
      // Capture the count before suspending: the caller may change the array afterwards.
      const count = items.length
      const results = await binding.signBatch(
        items.map((item) => ({ seed: item.privateKey, message: item.message })),
      )
      return assertResultCount(results, count)
    },
    async verify({ alg, signature, message, publicKey }: VerifyItem) {
      assertVerifying({ alg, signature, message, publicKey })
      if (alg === 'ES256')
        return await nodeCrypto.verify({
          alg,
          signature,
          message,
          publicKey,
        })
      return binding.verify({
        es256: false,
        signature,
        message,
        publicKey,
      })
    },
    async verifyBatch(items) {
      for (const item of items) {
        assertVerifying({
          alg: item.alg,
          signature: item.signature,
          message: item.message,
          publicKey: item.publicKey,
        })
      }
      // Capture membership before suspending: the caller may change the array afterwards.
      const algs = items.map((item) => item.alg)
      const ed25519 = items.filter((item) => item.alg === 'EdDSA')
      // Start both halves before awaiting either: nodeCrypto consumes its inputs synchronously
      // and the native batch copies them, so caller mutations afterwards change nothing.
      const es256 = items
        .filter((item) => item.alg === 'ES256')
        .map((item) => {
          return nodeCrypto.verify({
            alg: 'ES256',
            signature: item.signature,
            message: item.message,
            publicKey: item.publicKey,
          })
        })
      const native =
        ed25519.length === 0
          ? Promise.resolve([])
          : ed25519.length === 1
            ? Promise.resolve([
                binding.verify({
                  es256: false,
                  signature: (ed25519[0] as VerifyItem).signature,
                  message: (ed25519[0] as VerifyItem).message,
                  publicKey: (ed25519[0] as VerifyItem).publicKey,
                }),
              ])
            : binding
                .verifyBatch(
                  ed25519.map((item) => ({
                    es256: false,
                    signature: item.signature,
                    message: item.message,
                    publicKey: item.publicKey,
                  })),
                )
                .then((results) => assertResultCount(results, ed25519.length))
      const [edResults, esResults] = await Promise.all([native, Promise.all(es256)])
      let ed = 0
      let es = 0
      return algs.map((alg) => {
        return alg === 'EdDSA' ? (edResults[ed++] as boolean) : (esResults[es++] as boolean)
      })
    },
    async blake3({ input, dkLen }) {
      assertBytes(input)
      assertOutputLength(dkLen)
      return binding.blake3({ input, length: dkLen })
    },
    async blake3Batch({ inputs, dkLen }) {
      assertOutputLength(dkLen)
      for (const input of inputs) assertBytes(input)
      if (inputs.length === 0) return []
      const total = inputs.reduce((sum, input) => sum + input.length, 0)
      if (total <= BLAKE3_SYNC_BATCH_BYTES)
        return inputs.map((input) => binding.blake3({ input, length: dkLen }))
      const count = inputs.length
      return assertResultCount(await binding.blake3Batch({ inputs, length: dkLen }), count)
    },
  }
}

/**
 * The Rust core through Node-API when this platform's binary loads, otherwise `nodeCrypto`.
 * The choice is made once, here; a native failure after construction rejects instead of
 * falling back.
 */
export function createNapiCrypto(options: NapiCryptoOptions = {}): NapiCrypto {
  const loaded = options.binding !== undefined ? { binding: options.binding } : loadNapiBinding()
  if (loaded.binding == null) {
    const failure = 'failure' in loaded ? loaded.failure : undefined
    return { ...nodeCrypto, backend: 'node', ...(failure ? { failure } : {}) }
  }
  return { ...napiProvider(loaded.binding), backend: 'napi' }
}
