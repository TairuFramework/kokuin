import type * as NobleCurveModule from '@noble/curves/ed25519.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { beforeEach, expect, test, vi } from 'vitest'

const counts = vi.hoisted(() => ({ decoded: new Map<string, number>(), torsion: 0 }))
vi.mock('@noble/curves/ed25519.js', async (importOriginal) => {
  const actual = await importOriginal<typeof NobleCurveModule>()
  return {
    ed25519: {
      ...actual.ed25519,
      Point: {
        fromBytes(bytes: Uint8Array, zip215: boolean) {
          const key = bytesToHex(bytes)
          counts.decoded.set(key, (counts.decoded.get(key) ?? 0) + 1)
          const point = actual.ed25519.Point.fromBytes(bytes, zip215)
          return {
            isSmallOrder: () => point.isSmallOrder(),
            isTorsionFree() {
              counts.torsion++
              return point.isTorsionFree()
            },
          }
        },
      },
    },
  }
})
const { ed25519 } = await vi.importActual<typeof NobleCurveModule>('@noble/curves/ed25519.js')
beforeEach(() => {
  vi.resetModules()
  counts.decoded.clear()
  counts.torsion = 0
})

const message = new Uint8Array()
const seed = new Uint8Array(32).fill(71)
const publicKey = ed25519.getPublicKey(seed)
const signature = ed25519.sign(message, seed)

function strictPoint(bytes: Uint8Array): boolean {
  try {
    const point = ed25519.Point.fromBytes(bytes, false)
    return !point.isSmallOrder() && point.isTorsionFree()
  } catch {
    return false
  }
}

test('cached validation agrees with uncached valid, small-order and mixed-order keys', async () => {
  const { nobleCrypto } = await import('../src/noble.js')
  const torsion = ed25519.Point.fromBytes(new Uint8Array(32), false)
  const keys = [publicKey, torsion.toBytes(), ed25519.Point.BASE.add(torsion).toBytes()]
  expect(keys.map(strictPoint)).toEqual([true, false, false])
  for (const key of keys) {
    const expected = strictPoint(key) && ed25519.verify(signature, message, key, { zip215: false })
    for (let repeat = 0; repeat < 2; repeat++) {
      expect(
        await nobleCrypto.verify({
          alg: 'EdDSA',
          signature: signature,
          message: message,
          publicKey: key,
        }),
      ).toBe(expected)
    }
    expect(counts.decoded.get(bytesToHex(key))).toBe(1)
  }
})

test('repeated verification checks public-key torsion once and signature torsion every time', async () => {
  const { nobleCrypto } = await import('../src/noble.js')
  for (let repeat = 0; repeat < 3; repeat++) {
    expect(
      await nobleCrypto.verify({
        alg: 'EdDSA',
        signature: signature,
        message: message,
        publicKey: publicKey,
      }),
    ).toBe(true)
  }
  expect(counts.decoded.get(bytesToHex(publicKey))).toBe(1)
  expect(counts.torsion).toBe(4)
})

test('public-key validation evicts after 256 distinct keys', async () => {
  const { nobleCrypto } = await import('../src/noble.js')
  const keys = Array.from({ length: 257 }, (_, index) => {
    return ed25519.Point.BASE.multiply(BigInt(index + 1)).toBytes()
  })
  const rejectedR = new Uint8Array(64)
  for (const key of keys)
    await nobleCrypto.verify({
      alg: 'EdDSA',
      signature: rejectedR,
      message: message,
      publicKey: key,
    })
  counts.decoded.clear()
  const oldest = keys[0] as Uint8Array
  await nobleCrypto.verify({
    alg: 'EdDSA',
    signature: rejectedR,
    message: message,
    publicKey: oldest,
  })
  expect(counts.decoded.get(bytesToHex(oldest))).toBe(1)
  counts.decoded.clear()
  const newest = keys[256] as Uint8Array
  await nobleCrypto.verify({
    alg: 'EdDSA',
    signature: rejectedR,
    message: message,
    publicKey: newest,
  })
  expect(counts.decoded.has(bytesToHex(newest))).toBe(false)
  // 257 scalar multiplications and subgroup checks exceed the default under parallel suite load.
}, 30_000)

test('mutating an input view cannot reuse validation for different bytes', async () => {
  const { nobleCrypto } = await import('../src/noble.js')
  const backing = new Uint8Array(40)
  const key = backing.subarray(4, 36)
  key.set(publicKey)
  expect(
    await nobleCrypto.verify({
      alg: 'EdDSA',
      signature: signature,
      message: message,
      publicKey: key,
    }),
  ).toBe(true)
  key.fill(0)
  expect(
    await nobleCrypto.verify({
      alg: 'EdDSA',
      signature: signature,
      message: message,
      publicKey: key,
    }),
  ).toBe(false)
  key.set(publicKey)
  expect(
    await nobleCrypto.verify({
      alg: 'EdDSA',
      signature: signature,
      message: message,
      publicKey: key,
    }),
  ).toBe(true)
})
