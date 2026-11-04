import { Buffer } from 'node:buffer'
import { ed25519 } from '@noble/curves/ed25519.js'
import { fromB64U, fromUTF, toB64U } from '@sozai/codec'
import { beforeEach, expect, test } from 'vitest'

import { CODECS, getAlgorithmAndPublicKey } from '../src/did.js'
import { createIdentity, createSigningIdentity } from '../src/identity.js'
import { verifySignedPayload, verifyToken } from '../src/token.js'
import { clearVerifiedSignatureMemo, memoizeVerifier } from '../src/verified-memo.js'
import { getVerifier } from '../src/verifier.js'

beforeEach(clearVerifiedSignatureMemo)

test.each(['signature', 'message', 'publicKey'] as const)(
  'verification owns Buffer %s before yielding',
  async (field) => {
    const privateKey = ed25519.utils.randomSecretKey()
    const message = Buffer.from('original message')
    const publicKey = Buffer.from(ed25519.getPublicKey(privateKey))
    const signature = Buffer.from(ed25519.sign(message, privateKey))
    const pending = getVerifier('EdDSA')(signature, message, publicKey)
    ;({ signature, message, publicKey })[field].fill(0)
    await expect(pending).resolves.toBe(true)
  },
)

test.each(['signature', 'data'] as const)(
  'payload verification owns Buffer %s before resolving',
  async (field) => {
    const identity = createSigningIdentity(ed25519.utils.randomSecretKey())
    const token = await identity.signToken({ test: true })
    const signature = Buffer.from(fromB64U(token.signature))
    const data = Buffer.from(token.data)
    const pending = verifySignedPayload({ ...token, signature, data })
    ;({ signature, data })[field].fill(0)
    await expect(pending).resolves.toEqual(identity.publicKey)
  },
)

test.each(['single-key', 'multi-key'] as const)(
  '%s signing owns the Buffer private key before yielding',
  async (kind) => {
    const privateKey = Buffer.from(ed25519.utils.randomSecretKey())
    const identity =
      kind === 'single-key'
        ? createSigningIdentity(privateKey)
        : await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA', privateKey }] })
    const pending = identity.signToken({ test: true })
    privateKey.fill(0)
    const token = await pending
    expect(ed25519.verify(fromB64U(token.signature), fromUTF(token.data), identity.publicKey)).toBe(
      true,
    )
  },
)

test.each(['sync', 'async'] as const)(
  '%s memo storage owns the verified Buffer message',
  async (kind) => {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    const message = Buffer.from('original message')
    const signature = ed25519.sign(message, privateKey)
    const verify = memoizeVerifier(
      'EdDSA',
      kind === 'sync' ? ed25519.verify : async (...args) => ed25519.verify(...args),
    )
    expect(await verify(signature, message, publicKey)).toBe(true)
    message.fill(0)
    expect(await verify(signature, message, publicKey)).toBe(false)
  },
)

test('a replaced Buffer signature cannot poison the memo for a zero signature', async () => {
  const identity = createSigningIdentity(ed25519.utils.randomSecretKey())
  const token = await identity.signToken({ test: true })
  const signature = Buffer.alloc(64)
  const message = fromUTF(token.data)
  const pending = getVerifier('EdDSA')(signature, message, identity.publicKey)
  signature.set(fromB64U(token.signature))
  const accepted = await pending
  const zero = Buffer.alloc(64)
  expect(ed25519.verify(zero, message, identity.publicKey)).toBe(false)
  await expect(verifyToken({ ...token, signature: toB64U(zero) })).rejects.toThrow(
    'Invalid signature',
  )
  expect(accepted).toBe(false)
})

test('decoded public keys own caller Buffer bytes', () => {
  const publicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
  const encoded = Buffer.concat([CODECS.EdDSA, publicKey])
  const decoded = getAlgorithmAndPublicKey(encoded)
  encoded.fill(0)
  expect(decoded?.[1]).toEqual(publicKey)
})
