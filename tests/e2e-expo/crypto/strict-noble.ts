import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { blake3 } from '@noble/hashes/blake3.js'

import type { CryptoAlgorithm, SpikeCrypto } from './spike.js'

function assertBytes(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) {
    throw new TypeError('Expected an unshared Uint8Array')
  }
  new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
}

function sign(alg: 'EdDSA', seed: Uint8Array, message: Uint8Array): Uint8Array {
  if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
  assertBytes(seed)
  assertBytes(message)
  if (seed.length !== 32) throw new TypeError('Expected a 32-byte Ed25519 seed')
  return ed25519.sign(message, seed)
}

function strictPoint(bytes: Uint8Array): boolean {
  const point = ed25519.Point.fromBytes(bytes, false)
  return !point.isSmallOrder() && point.isTorsionFree()
}

function verify(
  alg: CryptoAlgorithm,
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (alg !== 'EdDSA' && alg !== 'ES256') throw new TypeError('Unsupported verification algorithm')
  for (const bytes of [signature, message, publicKey]) assertBytes(bytes)
  if (signature.length !== 64) return false
  try {
    if (alg === 'EdDSA') {
      return (
        publicKey.length === 32 &&
        strictPoint(publicKey) &&
        strictPoint(signature.subarray(0, 32)) &&
        ed25519.verify(signature, message, publicKey, { zip215: false })
      )
    }
    if (
      !(
        (publicKey.length === 33 && (publicKey[0] === 2 || publicKey[0] === 3)) ||
        (publicKey.length === 65 && publicKey[0] === 4)
      )
    )
      return false
    return p256.verify(signature, message, publicKey, {
      lowS: true,
      prehash: true,
      format: 'compact',
    })
  } catch {
    return false
  }
}

function assertOutputLength(dkLen: number): void {
  if (!Number.isInteger(dkLen) || dkLen < 1 || dkLen > 65536)
    throw new RangeError('Invalid blake3 output length')
}

function hash(input: Uint8Array, dkLen: number): Uint8Array {
  assertBytes(input)
  assertOutputLength(dkLen)
  return blake3(input, { dkLen })
}

// Inputs are consumed synchronously before the Promise is returned.
export const strictNoble: SpikeCrypto = {
  async sign(alg, seed, message) {
    return sign(alg, seed, message)
  },
  async signBatch(alg, items) {
    if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
    return items.map((item) => sign(alg, item.privateKey, item.message))
  },
  async verify(alg, signature, message, publicKey) {
    return verify(alg, signature, message, publicKey)
  },
  async verifyBatch(items) {
    return items.map((item) => verify(item.alg, item.signature, item.message, item.publicKey))
  },
  async blake3(input, dkLen) {
    return hash(input, dkLen)
  },
  async blake3Batch(inputs, dkLen) {
    assertOutputLength(dkLen)
    return inputs.map((input) => hash(input, dkLen))
  },
}
