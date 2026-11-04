import type { CryptoAlgorithm, CryptoProvider } from '@kokuin/crypto'
import { nodeCrypto } from '@kokuin/crypto-node'

import { loadNapiBinding, type NapiBinding, type NapiLoadFailure } from './binding.js'

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

function assertVerifying(
  alg: CryptoAlgorithm,
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): void {
  if (alg !== 'EdDSA' && alg !== 'ES256') throw new TypeError('Unsupported verification algorithm')
  for (const bytes of [signature, message, publicKey]) assertBytes(bytes)
}

function assertOutputLength(dkLen: number): void {
  if (!Number.isInteger(dkLen) || dkLen < 1 || dkLen > 65536)
    throw new RangeError('Invalid blake3 output length')
}

/**
 * Routes, measured on x86_64 (see docs/reference/crypto-provider.md):
 * - Ed25519 sign, Ed25519 verify and blake3 single calls run natively on the calling thread.
 * - ES256 single calls use `nodeCrypto`, whose OpenSSL verifier is faster than the Rust one.
 * - Every batch copies its inputs on the calling thread, then runs natively on the libuv pool.
 *
 * Arguments are validated in JavaScript exactly as `nobleCrypto` validates them, so every
 * backend raises the same error types. Every method consumes its inputs before its Promise
 * returns.
 */
function napiProvider(binding: NapiBinding): CryptoProvider {
  return {
    async sign(alg, seed, message) {
      assertSigning(alg, seed, message)
      return binding.sign(seed, message)
    },
    async signBatch(alg, items) {
      if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
      for (const item of items) assertSigning(alg, item.privateKey, item.message)
      if (items.length === 0) return []
      return await binding.signBatch(
        items.map((item) => item.privateKey),
        items.map((item) => item.message),
      )
    },
    async verify(alg, signature, message, publicKey) {
      assertVerifying(alg, signature, message, publicKey)
      if (alg === 'ES256') return await nodeCrypto.verify(alg, signature, message, publicKey)
      return binding.verify(false, signature, message, publicKey)
    },
    async verifyBatch(items) {
      for (const item of items) {
        assertVerifying(item.alg, item.signature, item.message, item.publicKey)
      }
      if (items.length === 0) return []
      return await binding.verifyBatch(
        items.map((item) => item.alg === 'ES256'),
        items.map((item) => item.signature),
        items.map((item) => item.message),
        items.map((item) => item.publicKey),
      )
    },
    async blake3(input, dkLen) {
      assertBytes(input)
      assertOutputLength(dkLen)
      return binding.blake3(input, dkLen)
    },
    async blake3Batch(inputs, dkLen) {
      assertOutputLength(dkLen)
      for (const input of inputs) assertBytes(input)
      if (inputs.length === 0) return []
      return await binding.blake3Batch(inputs, dkLen)
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
