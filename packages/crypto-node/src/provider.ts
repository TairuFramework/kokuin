import {
  createPrivateKey,
  createPublicKey,
  ECDH,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto'
import { type CryptoAlgorithm, type CryptoProvider, nobleCrypto } from '@kokuin/crypto'

// Ed25519 seed as a PKCS #8 PrivateKeyInfo (RFC 8410): this 16-byte prefix, then the 32-byte seed.
const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
])
// P-256 SubjectPublicKeyInfo (RFC 5480) for an uncompressed point: this prefix, then 65 bytes.
const SPKI_P256_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
])
const P256_HALF_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n >> 1n

function assertBytes(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) {
    throw new TypeError('Expected an unshared Uint8Array')
  }
  // Throws TypeError on a detached buffer.
  new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
}

function sign(alg: 'EdDSA', seed: Uint8Array, message: Uint8Array): Uint8Array {
  if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
  assertBytes(seed)
  assertBytes(message)
  if (seed.length !== 32) throw new TypeError('Expected a 32-byte Ed25519 seed')
  const der = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32)
  der.set(PKCS8_ED25519_PREFIX)
  der.set(seed, PKCS8_ED25519_PREFIX.length)
  try {
    const key = createPrivateKey({ key: Buffer.from(der.buffer), format: 'der', type: 'pkcs8' })
    // Copy into a plain, independently owned Uint8Array rather than handing out a Buffer.
    return new Uint8Array(nodeSign(null, message, key))
  } finally {
    // OpenSSL holds its own copy for the KeyObject's lifetime; do not leave a second one here.
    der.fill(0)
  }
}

function bigIntBE(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value
}

function verifyES256(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  for (const bytes of [signature, message, publicKey]) assertBytes(bytes)
  if (signature.length !== 64) return false
  if (
    !(
      (publicKey.length === 33 && (publicKey[0] === 2 || publicKey[0] === 3)) ||
      (publicKey.length === 65 && publicKey[0] === 4)
    )
  )
    return false
  // OpenSSL accepts both s and n - s. The contract rejects the malleable high half.
  if (bigIntBE(signature.subarray(32)) > P256_HALF_ORDER) return false
  try {
    // Decompression throws for an x with no point on the curve; SPKI import rejects off-curve
    // uncompressed points. OpenSSL checks 0 < r, s < n and the ECDSA equation.
    const point =
      publicKey.length === 33
        ? new Uint8Array(
            ECDH.convertKey(
              publicKey,
              'prime256v1',
              undefined,
              undefined,
              'uncompressed',
            ) as Buffer,
          )
        : publicKey
    const spki = new Uint8Array(SPKI_P256_PREFIX.length + 65)
    spki.set(SPKI_P256_PREFIX)
    spki.set(point, SPKI_P256_PREFIX.length)
    const key = createPublicKey({ key: Buffer.from(spki.buffer), format: 'der', type: 'spki' })
    return nodeVerify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature)
  } catch {
    return false
  }
}

function verifyOne(
  alg: CryptoAlgorithm,
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  // Never throw synchronously: in a batch, an earlier item's rejected Promise would then never
  // reach Promise.all and would surface as an unhandled rejection.
  try {
    if (alg !== 'EdDSA' && alg !== 'ES256') {
      throw new TypeError('Unsupported verification algorithm')
    }
    if (alg === 'ES256') return Promise.resolve(verifyES256(signature, message, publicKey))
    return nobleCrypto.verify(alg, signature, message, publicKey)
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Ed25519 signing and ES256 verification run through `node:crypto` (OpenSSL); Ed25519
 * verification and blake3 delegate to strict noble. OpenSSL accepts small-order and mixed-order
 * Ed25519 points the contract rejects, and node:crypto has no blake3.
 *
 * Every method consumes its inputs synchronously before its Promise is returned. noble's async
 * methods do the same, so delegating to them preserves that.
 */
export const nodeCrypto: CryptoProvider = {
  async sign(alg, seed, message) {
    return sign(alg, seed, message)
  },
  async signBatch(alg, items) {
    if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
    return items.map((item) => sign(alg, item.privateKey, item.message))
  },
  async verify(alg, signature, message, publicKey) {
    return await verifyOne(alg, signature, message, publicKey)
  },
  async verifyBatch(items) {
    return await Promise.all(
      items.map((item) => verifyOne(item.alg, item.signature, item.message, item.publicKey)),
    )
  },
  blake3(input, dkLen) {
    return nobleCrypto.blake3(input, dkLen)
  },
  blake3Batch(inputs, dkLen) {
    return nobleCrypto.blake3Batch(inputs, dkLen)
  },
}
