import { createPublicKey, ECDH, verify as opensslVerify, randomBytes } from 'node:crypto'
import { runInNewContext } from 'node:vm'
import { nobleCrypto } from '@kokuin/crypto'
import { corpus, cryptoConformance, externalConformance } from '@kokuin/crypto-conformance'
import { p256 } from '@noble/curves/nist.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { expect, test } from 'vitest'

import { nodeCrypto } from '../src/index.js'

const N = p256.Point.CURVE().n
// The random comparisons run strict noble ES256 at about 1.7 ms per operation, which a loaded CI
// runner stretches past the 5s default.
const RANDOM = { timeout: 30_000 }

function vector(name: string) {
  const entry = corpus.verify.find((candidate) => candidate.name === name)
  if (entry == null) throw new Error(`missing corpus vector ${name}`)
  return {
    signature: hexToBytes(entry.signature),
    message: hexToBytes(entry.message),
    publicKey: hexToBytes(entry.publicKey),
  }
}

test('runs the complete provider contract', async () => {
  for (const entry of cryptoConformance(nodeCrypto)) await entry.run()
})

// About a thousand operations, half on strict noble: about 1s locally, far slower on a busy runner.
test('passes every pinned upstream vector', { timeout: 120_000 }, async () => {
  for (const entry of externalConformance(nodeCrypto)) await entry.run()
})

test('the low-S guard is load bearing: OpenSSL alone accepts the high-S vector', async () => {
  const { signature, message, publicKey } = vector('ES256 high-S')
  const raw = ECDH.convertKey(publicKey, 'prime256v1', undefined, undefined, 'uncompressed')
  const key = createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64u(raw.subarray(1, 33)), y: b64u(raw.subarray(33)) },
    format: 'jwk',
  })
  expect(opensslVerify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature)).toBe(true)
  expect(
    await nodeCrypto.verify({
      alg: 'ES256',
      signature,
      message,
      publicKey,
    }),
  ).toBe(false)
})

test('rejects a compressed key whose x has no point on the curve', async () => {
  const { signature, message } = vector('ES256 compact low-S')
  let x = 0n
  for (; ; x++) {
    try {
      p256.Point.fromBytes(Uint8Array.of(2, ...numberToBytesBE(x, 32)))
    } catch {
      break
    }
  }
  const offCurve = Uint8Array.of(2, ...numberToBytesBE(x, 32))
  expect(
    await nodeCrypto.verify({
      alg: 'ES256',
      signature,
      message,
      publicKey: offCurve,
    }),
  ).toBe(false)
  expect(
    await nobleCrypto.verify({
      alg: 'ES256',
      signature,
      message,
      publicKey: offCurve,
    }),
  ).toBe(false)
})

test('agrees with strict noble on random Ed25519 signatures', RANDOM, async () => {
  for (let i = 0; i < 32; i++) {
    const seed = new Uint8Array(randomBytes(32))
    const message = new Uint8Array(randomBytes(i * 73))
    expect(await nodeCrypto.sign({ alg: 'EdDSA', privateKey: seed, message })).toEqual(
      await nobleCrypto.sign({ alg: 'EdDSA', privateKey: seed, message }),
    )
  }
})

test('agrees with strict noble on random ES256 verifications', RANDOM, async () => {
  for (let i = 0; i < 16; i++) {
    const secret = p256.utils.randomSecretKey()
    const publicKey = p256.getPublicKey(secret, i % 2 === 0)
    const message = new Uint8Array(randomBytes(i * 83))
    const signature = p256.sign(message, secret, { lowS: true, prehash: true, format: 'compact' })
    const high = signature.slice()
    high.set(numberToBytesBE(N - bytesToNumberBE(signature.subarray(32)), 32), 32)
    const mutated = message.length === 0 ? Uint8Array.of(1) : message.map((byte) => byte ^ 1)
    const otherKey = p256.getPublicKey(p256.utils.randomSecretKey(), i % 2 === 1)
    for (const [sig, msg, key] of [
      [signature, message, publicKey],
      [high, message, publicKey],
      [signature, mutated, publicKey],
      [signature, message, otherKey],
    ] as const) {
      expect(
        await nodeCrypto.verify({ alg: 'ES256', signature: sig, message: msg, publicKey: key }),
      ).toBe(
        await nobleCrypto.verify({ alg: 'ES256', signature: sig, message: msg, publicKey: key }),
      )
    }
    expect(
      await nodeCrypto.verify({
        alg: 'ES256',
        signature,
        message,
        publicKey,
      }),
    ).toBe(true)
  }
})

test('rejects shared and detached ES256 inputs like noble', async () => {
  const { signature, message, publicKey } = vector('ES256 compact low-S')
  const shared = new Uint8Array(new SharedArrayBuffer(64))
  shared.set(signature)
  await expect(
    nodeCrypto.verify({ alg: 'ES256', signature: shared, message, publicKey }),
  ).rejects.toThrow(TypeError)
  const detached = message.slice()
  structuredClone(detached.buffer, { transfer: [detached.buffer] })
  await expect(
    nodeCrypto.verify({
      alg: 'ES256',
      signature,
      message: detached,
      publicKey,
    }),
  ).rejects.toThrow(TypeError)
  await expect(
    nodeCrypto.verify({
      alg: 'RS256' as 'ES256',
      signature,
      message,
      publicKey,
    }),
  ).rejects.toThrow(TypeError)
})

test('returns plain, independently owned signatures', async () => {
  const seed = new Uint8Array(32).fill(7)
  const [first, second] = await nodeCrypto.signBatch({
    alg: 'EdDSA',
    items: [
      { privateKey: seed, message: new Uint8Array() },
      { privateKey: seed, message: new Uint8Array() },
    ],
  })
  expect(Object.getPrototypeOf(first)).toBe(Uint8Array.prototype)
  first?.fill(0)
  expect(second).toEqual(
    await nobleCrypto.sign({ alg: 'EdDSA', privateKey: seed, message: new Uint8Array() }),
  )
})

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

test('a batch with several invalid items rejects once, leaving no unhandled rejection', async () => {
  const unhandled: Array<unknown> = []
  const record = (reason: unknown) => unhandled.push(reason)
  process.on('unhandledRejection', record)
  try {
    const shared = new Uint8Array(new SharedArrayBuffer(64))
    const valid = vector('ES256 compact low-S')
    await expect(
      nodeCrypto.verifyBatch([
        { alg: 'EdDSA', signature: shared, message: new Uint8Array(), publicKey: shared },
        { alg: 'ES256', signature: shared, message: valid.message, publicKey: valid.publicKey },
      ]),
    ).rejects.toThrow(TypeError)
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(unhandled).toEqual([])
  } finally {
    process.off('unhandledRejection', record)
  }
})

test('accepts byte inputs from another realm', async () => {
  const provider = nodeCrypto
  const input: Uint8Array = runInNewContext('new Uint8Array([1, 2, 3])')
  expect(input instanceof Uint8Array).toBe(false)
  const local = new Uint8Array([1, 2, 3])
  expect(
    await provider.sign({ alg: 'EdDSA', privateKey: new Uint8Array(32), message: input }),
  ).toEqual(await provider.sign({ alg: 'EdDSA', privateKey: new Uint8Array(32), message: local }))
})

test('rejects shared byte inputs from any realm', async () => {
  const provider = nodeCrypto
  const foreign: Uint8Array = runInNewContext('new Uint8Array(new SharedArrayBuffer(3))')
  for (const input of [new Uint8Array(new SharedArrayBuffer(3)), foreign]) {
    await expect(
      provider.sign({ alg: 'EdDSA', privateKey: new Uint8Array(32), message: input }),
    ).rejects.toThrow('Expected an unshared Uint8Array')
  }
})
