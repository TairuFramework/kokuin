import { readFileSync } from 'node:fs'
import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { concatBytes, hexToBytes } from '@noble/hashes/utils.js'
import { b64uFromJSON, fromB64U, fromUTF, toB64U } from '@sozai/codec'
import { beforeEach, expect, test } from 'vitest'

import { CODECS, getDID } from '../src/did.js'
import {
  createFullIdentity,
  createIdentity,
  createSigningIdentity,
  createSigningIdentityForDID,
  randomIdentity,
} from '../src/identity.js'
import { verifySignedPayload, verifyToken } from '../src/token.js'
import { clearVerifiedSignatureMemo, verifiedSignatureMemoSize } from '../src/verified-memo.js'
import { getVerifier } from '../src/verifier.js'

function provider(verify?: CryptoProvider['verify']) {
  const calls = { sign: 0, signBatch: 0, verify: 0, verifyBatch: 0, blake3: 0, blake3Batch: 0 }
  const inputs: Array<{
    alg: string
    signature?: Uint8Array
    message: Uint8Array
    key: Uint8Array
  }> = []
  const crypto: CryptoProvider = {
    async sign(alg, key, message) {
      calls.sign++
      inputs.push({ alg, message: message.slice(), key: key.slice() })
      return nobleCrypto.sign(alg, key, message)
    },
    async signBatch(alg, items) {
      calls.signBatch++
      return nobleCrypto.signBatch(alg, items)
    },
    async verify(alg, signature, message, key) {
      calls.verify++
      inputs.push({ alg, signature: signature.slice(), message: message.slice(), key: key.slice() })
      return (verify ?? nobleCrypto.verify)(alg, signature, message, key)
    },
    async verifyBatch(items) {
      calls.verifyBatch++
      return nobleCrypto.verifyBatch(items)
    },
    async blake3(input, length) {
      calls.blake3++
      return nobleCrypto.blake3(input, length)
    },
    async blake3Batch(inputs, length) {
      calls.blake3Batch++
      return nobleCrypto.blake3Batch(inputs, length)
    },
  }
  return { crypto, calls, inputs }
}

beforeEach(clearVerifiedSignatureMemo)

test('identity helpers capture the provider and sign exact raw JWS bytes', async () => {
  const routed = provider()
  const options = { crypto: routed.crypto }
  const seed = new Uint8Array(32).fill(7)
  const identities = [
    createSigningIdentity(seed, options),
    createFullIdentity(seed, options),
    randomIdentity(options),
    createSigningIdentityForDID('did:kokuin:test', seed, options),
    await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA', privateKey: seed }],
      crypto: routed.crypto,
    }),
    await createIdentity({
      didMethod: 'peer:4',
      keys: [{ purpose: 'sig', alg: 'EdDSA', privateKey: seed }],
      crypto: routed.crypto,
    }),
  ]
  options.crypto = provider().crypto
  for (const identity of identities) {
    const token = await identity.signToken({ hello: 'world' })
    const input = routed.inputs.at(-1)
    if (input === undefined) throw new Error('Missing signing input')
    expect(input.message).toEqual(fromUTF(token.data))
    expect(fromB64U(token.signature)).toEqual(ed25519.sign(fromUTF(token.data), input.key))
  }
  expect(routed.calls).toEqual({
    sign: 6,
    signBatch: 0,
    verify: 0,
    verifyBatch: 0,
    blake3: 0,
    blake3Batch: 0,
  })
})

test('provider and verifier identity partition both verification caches', async () => {
  const token = await randomIdentity().signToken({ test: 'policy' })
  const permissive = provider(async () => true)
  const rejecting = provider(async () => false)
  const verified = await verifyToken(token, { crypto: permissive.crypto })
  expect(await verifyToken(verified, { crypto: permissive.crypto })).toBe(verified)
  await verifyToken(token, { crypto: permissive.crypto })
  expect(permissive.calls.verify).toBe(1)
  await expect(verifyToken(verified, { crypto: rejecting.crypto })).rejects.toThrow(
    'Invalid signature',
  )
  await expect(verifyToken(token, { crypto: rejecting.crypto })).rejects.toThrow(
    'Invalid signature',
  )
  expect(rejecting.calls.verify).toBe(2)
  let overrides = 0
  const custom = await verifyToken(verified, {
    crypto: rejecting.crypto,
    verifiers: {
      EdDSA: () => {
        overrides++
        return true
      },
    },
  })
  await expect(verifyToken(custom, { crypto: rejecting.crypto })).rejects.toThrow(
    'Invalid signature',
  )
  expect(overrides).toBe(1)
  expect(verifiedSignatureMemoSize()).toBe(1)
})

test('concurrent providers and operational failures cannot cache acceptance', async () => {
  const token = await randomIdentity().signToken({ test: 'concurrent' })
  const sentinel = new Error('provider unavailable')
  const accepted = provider(async () => true)
  const failed = provider(async () => {
    throw sentinel
  })
  const results = await Promise.allSettled([
    verifyToken(token, { crypto: accepted.crypto }),
    verifyToken(token, { crypto: failed.crypto }),
  ])
  expect(results[0]?.status).toBe('fulfilled')
  expect(results[1]).toEqual({ status: 'rejected', reason: sentinel })
  const verified = await verifyToken(token, { crypto: accepted.crypto })
  for (const input of [token, verified])
    await expect(verifyToken(input, { crypto: failed.crypto })).rejects.toBe(sentinel)
  expect(failed.calls.verify).toBe(3)
  expect(verifiedSignatureMemoSize()).toBe(1)
})

test('algorithm overrides suppress only their selected provider operation', async () => {
  const routed = provider()
  const ed = await randomIdentity().signToken({ test: 'override' })
  const key = new Uint8Array(32).fill(8)
  const header = { typ: 'JWT', alg: 'ES256' }
  const payload = { iss: getDID(CODECS.ES256, p256.getPublicKey(key)) }
  const data = `${b64uFromJSON(header)}.${b64uFromJSON(payload)}`
  const signature = p256.sign(fromUTF(data), key, { format: 'compact', prehash: true, lowS: true })
  const es = `${data}.${toB64U(signature)}`
  await verifyToken(ed, { crypto: routed.crypto, verifiers: { EdDSA: () => true } })
  expect(routed.calls.verify).toBe(0)
  await verifyToken(es, { crypto: routed.crypto, verifiers: { EdDSA: () => false } })
  expect(routed.inputs[0]).toEqual({
    alg: 'ES256',
    signature,
    message: fromUTF(data),
    key: p256.getPublicKey(key),
  })
  await verifyToken(ed, { crypto: routed.crypto, verifiers: { ES256: () => false } })
  expect(routed.calls.verify).toBe(2)
  const highS = p256.Signature.fromBytes(signature).addRecoveryBit(0)
  const high = new p256.Signature(highS.r, p256.Point.Fn.ORDER - highS.s).toBytes()
  await expect(verifyToken(`${data}.${toB64U(high)}`, { crypto: routed.crypto })).rejects.toThrow(
    'Invalid signature',
  )
})

test('verified objects re-resolve changed method and resolver policy', async () => {
  const identity = createSigningIdentityForDID('did:kokuin:test', new Uint8Array(32).fill(3))
  const method = {
    method: 'kokuin',
    resolve: async () => ({ alg: 'EdDSA' as const, publicKey: identity.publicKey }),
  }
  const token = await identity.signToken({ test: 'context' })
  const verified = await verifyToken(token, { methods: [method] })
  await expect(verifyToken(verified)).rejects.toThrow('Unknown DID')
  method.resolve = async () => ({
    alg: 'EdDSA',
    publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(4)),
  })
  await expect(verifyToken(verified, { methods: [method] })).rejects.toThrow('Invalid signature')
})

test('signature and claimed public key mutations cannot reuse object provenance', async () => {
  const verified = await verifyToken(await randomIdentity().signToken({ test: 'signature' }))
  verified.signature = toB64U(new Uint8Array(64))
  await expect(verifyToken(verified)).rejects.toThrow('Invalid signature')
})

test('verification snapshots caller bytes and override policy before resolving', async () => {
  const identity = createSigningIdentityForDID('did:kokuin:test', new Uint8Array(32).fill(5))
  const token = await identity.signToken({ test: 'snapshot' })
  let release!: () => void
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const methods = [
    {
      method: 'kokuin',
      resolve: async () => {
        await gate
        return { alg: 'EdDSA' as const, publicKey: identity.publicKey }
      },
    },
  ]
  const signature = fromB64U(token.signature)
  const data = fromUTF(token.data)
  const verifiers = { EdDSA: () => true }
  const pending = verifySignedPayload({
    signature,
    data,
    header: token.header,
    payload: token.payload,
    methods,
    verifiers,
  })
  signature.fill(0)
  data.fill(0)
  verifiers.EdDSA = () => false
  release()
  await expect(pending).resolves.toEqual(identity.publicKey)
  const pendingToken = verifyToken(token, { methods })
  token.payload.test = 'mutated'
  release()
  expect((await pendingToken).payload.test).toBe('snapshot')
})

test('memoized provider inputs are owned before cooperative yield', async () => {
  const routed = provider()
  const seed = new Uint8Array(32).fill(6)
  const key = ed25519.getPublicKey(seed)
  const message = fromUTF('unchanged')
  const signature = ed25519.sign(message, seed)
  const pending = getVerifier('EdDSA', undefined, { crypto: routed.crypto })(
    signature,
    message,
    key,
  )
  signature.fill(0)
  message.fill(0)
  key.fill(0)
  await expect(pending).resolves.toBe(true)
})

test('default strict verification rejects message-independent ZIP-215 forgeries', async () => {
  const vector = corpus.verify.find(
    (entry) => entry.name === 'Ed25519 identity public key and R with S = 0',
  )
  if (vector === undefined) throw new Error('Missing identity corpus fixture')
  const key = hexToBytes(vector.publicKey)
  const signature = hexToBytes(vector.signature)
  const header = { typ: 'JWT', alg: 'EdDSA' }
  const payload = { iss: getDID(CODECS.EdDSA, key) }
  const data = `${b64uFromJSON(header)}.${b64uFromJSON(payload)}`
  expect(ed25519.verify(signature, fromUTF(data), key, { zip215: true })).toBe(true)
  await expect(verifyToken(`${data}.${toB64U(signature)}`)).rejects.toThrow('Invalid signature')
  await expect(
    verifyToken(`${data}.${toB64U(signature)}`, { verifiers: { EdDSA: () => true } }),
  ).resolves.toBeDefined()
})

test('cached objects enforce audience, time, mutation and default-provider equivalence', async () => {
  const token = await randomIdentity().signToken({ aud: 'did:key:service', exp: 200 })
  const verified = await verifyToken(token, { atTime: 100 })
  expect(
    await verifyToken(verified, { crypto: nobleCrypto, atTime: 100, audience: 'did:key:service' }),
  ).toBe(verified)
  await expect(verifyToken(verified, { atTime: 201 })).rejects.toThrow('Token expired')
  await expect(verifyToken(verified, { atTime: 100, audience: 'did:key:other' })).rejects.toThrow(
    'audience',
  )
  verified.payload.aud = 'did:key:other'
  await expect(verifyToken(verified, { atTime: 100 })).rejects.toThrow('data does not match')
})

test('cache context and resolver identity cannot reuse peer document provenance', async () => {
  const identity = await createIdentity({
    didMethod: 'peer:4',
    keys: [{ purpose: 'sig', alg: 'EdDSA' }],
  })
  const token = await identity.signToken({ test: true }, { embedLongForm: false })
  const resolver = async () => identity.doc
  const verified = await verifyToken(token, { resolver })
  await expect(verifyToken(verified, { resolver: async () => undefined })).rejects.toThrow()
  await expect(verifyToken(verified)).rejects.toThrow()
})

test('resolver instances retain their method receiver', async () => {
  const identity = createSigningIdentityForDID('did:kokuin:test', new Uint8Array(32).fill(11))
  class Resolver {
    method = 'kokuin'
    #key = identity.publicKey
    async resolve() {
      return { alg: 'EdDSA' as const, publicKey: this.#key }
    }
  }
  const methods = [new Resolver()]
  const token = await identity.signToken({ test: 'receiver' })
  await expect(verifyToken(token, { methods })).resolves.toBeDefined()
})

const corpus = JSON.parse(
  readFileSync(new URL('../../crypto-conformance/vectors/corpus.json', import.meta.url), 'utf8'),
) as {
  verify: Array<{ name: string; publicKey: string; signature: string; message: string }>
}

for (const remainder of [0n, 3n]) {
  test(`strict verification rejects a correctly framed mixed-order key with challenge ${remainder}`, async () => {
    const vector = corpus.verify.find(
      (entry) => entry.name === `Ed25519 mixed-order public key, k = ${remainder} mod 4`,
    )
    if (vector === undefined) throw new Error('Missing mixed-order corpus fixture')
    const key = hexToBytes(vector.publicKey)
    const r = hexToBytes(vector.signature).slice(0, 32)
    const header = { typ: 'JWT', alg: 'EdDSA' }
    let data = ''
    let challenge = 0n
    for (let nonce = 0; ; nonce++) {
      const payload = { iss: getDID(CODECS.EdDSA, key), nonce }
      data = `${b64uFromJSON(header)}.${b64uFromJSON(payload)}`
      challenge =
        bytesToNumberLE(sha512(concatBytes(r, key, fromUTF(data)))) % ed25519.Point.Fn.ORDER
      if (challenge % 4n === remainder) break
    }
    const signature = concatBytes(r, numberToBytesLE((1n + challenge) % ed25519.Point.Fn.ORDER, 32))
    expect(ed25519.verify(signature, fromUTF(data), key, { zip215: true })).toBe(true)
    expect(ed25519.verify(signature, fromUTF(data), key, { zip215: false })).toBe(true)
    await expect(verifyToken(`${data}.${toB64U(signature)}`)).rejects.toThrow('Invalid signature')
  })
}

test('DID cache methods are captured before asynchronous verification', async () => {
  const identity = await createIdentity({
    didMethod: 'peer:4',
    keys: [{ purpose: 'sig', alg: 'EdDSA' }],
  })
  let release!: () => void
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  let writes = 0
  const cache = {
    get() {
      return undefined
    },
    set() {
      writes++
    },
  }
  const routed = provider(async () => {
    await gate
    return true
  })
  const pending = verifyToken(await identity.signToken({ value: 'cache' }), {
    cache,
    crypto: routed.crypto,
  })
  cache.set = () => {
    throw new Error('replacement cache writer')
  }
  release()
  await expect(pending).resolves.toBeDefined()
  expect(writes).toBe(1)
})

test('captured verifier functions partition object provenance after override mutation', async () => {
  const token = await randomIdentity().signToken({ value: 'override identity' })
  const verifiers = { EdDSA: () => true }
  const verified = await verifyToken(token, { verifiers })
  let calls = 0
  verifiers.EdDSA = () => {
    calls++
    return false
  }
  await expect(verifyToken(verified, { verifiers })).rejects.toThrow('Invalid signature')
  expect(calls).toBe(1)
})

for (const serialized of [false, true]) {
  test(`audience policy is captured before suspended ${serialized ? 'serialized' : 'object'} verification`, async () => {
    const token = await randomIdentity().signToken({ aud: 'did:key:other' })
    let release!: () => void
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const routed = provider(async () => {
      await gate
      return true
    })
    const audience: Array<`did:${string}:${string}`> = ['did:key:expected']
    const pending = verifyToken(serialized ? `${token.data}.${token.signature}` : token, {
      crypto: routed.crypto,
      audience,
    })
    audience[0] = 'did:key:other'
    release()
    await expect(pending).rejects.toThrow('audience')
  })
}
