import { nobleCrypto } from '@kokuin/crypto'
import { p256 } from '@noble/curves/nist.js'
import type * as SozaiAsync from '@sozai/async'
import { maybeYield } from '@sozai/async'
import { b64uFromJSON, fromB64U, fromUTF, toB64U } from '@sozai/codec'
import { beforeEach, expect, test, vi } from 'vitest'

import { CODECS, getDID } from '../src/did.js'
import {
  createFullIdentity,
  createIdentity,
  createSigningIdentity,
  createSigningIdentityForDID,
  randomIdentity,
} from '../src/identity.js'
import { createUnsignedToken, signToken, verifySignedPayload, verifyToken } from '../src/token.js'
import { clearVerifiedSignatureMemo } from '../src/verified-memo.js'
import { getVerifier } from '../src/verifier.js'

vi.mock('@sozai/async', async (importOriginal) => {
  const original = await importOriginal<typeof SozaiAsync>()
  return { ...original, maybeYield: vi.fn(original.maybeYield) }
})

const yieldSpy = vi.mocked(maybeYield)
const privateKey = new Uint8Array(32).fill(7)

beforeEach(() => {
  clearVerifiedSignatureMemo()
  yieldSpy.mockClear()
})

const factories = {
  signing: () => createSigningIdentity({ privateKey }),
  full: () => createFullIdentity({ privateKey }),
  random: () => randomIdentity(),
  suppliedDID: () => createSigningIdentityForDID({ id: 'did:kokuin:yield', privateKey }),
  multiKey: () => createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA', privateKey }] }),
  peer: () => {
    return createIdentity({
      didMethod: 'peer:4',
      keys: [{ purpose: 'sig', alg: 'EdDSA', privateKey }],
    })
  },
}

for (const [name, factory] of Object.entries(factories)) {
  test(`${name} signing can skip the yielder without changing signed bytes`, async () => {
    const identity = await factory()
    const payload = { action: 'write', aud: 'did:key:recipient' }
    const options = { payload, embedLongForm: true }
    const withoutYield = await identity.signToken({ ...options, yield: false })
    expect(yieldSpy).not.toHaveBeenCalled()
    const normal = await identity.signToken(options)
    expect(yieldSpy).toHaveBeenCalledTimes(1)
    expect(withoutYield).toEqual(normal)
    expect(
      await nobleCrypto.verify({
        alg: 'EdDSA',
        publicKey: identity.publicKey,
        signature: fromB64U(withoutYield.signature),
        message: fromUTF(withoutYield.data),
      }),
    ).toBe(true)
  })
}

test('signToken forwards the yield policy and preserves already signed tokens', async () => {
  const signer = createSigningIdentity({ privateKey })
  const token = createUnsignedToken({ payload: { action: 'write' } })
  const signed = await signToken({ signer, token, yield: false })
  expect(yieldSpy).not.toHaveBeenCalled()
  expect(await signToken({ signer, token })).toEqual(signed)
  expect(yieldSpy).toHaveBeenCalledTimes(1)
  yieldSpy.mockClear()
  expect(await signToken({ signer, token: signed, yield: false })).toBe(signed)
  expect(yieldSpy).not.toHaveBeenCalled()
})

for (const alg of ['EdDSA', 'ES256'] as const) {
  for (const serialized of [false, true]) {
    test(`${alg} ${serialized ? 'serialized' : 'object'} cache-miss verification skips only yielding`, async () => {
      const identity = createSigningIdentity({ privateKey })
      const token = await identity.signToken({ payload: { action: 'write' } })
      if (alg === 'ES256') {
        token.header.alg = alg
        token.payload.iss = getDID({
          codec: CODECS.ES256,
          publicKey: p256.getPublicKey(privateKey),
        })
        token.data = `${b64uFromJSON(token.header)}.${b64uFromJSON(token.payload)}`
        token.signature = toB64U(
          p256.sign(fromUTF(token.data), privateKey, { prehash: true, lowS: true }),
        )
      }
      const input = serialized ? `${token.data}.${token.signature}` : token
      yieldSpy.mockClear()
      const disabled = await verifyToken({ token: input, yield: false })
      expect(yieldSpy).not.toHaveBeenCalled()
      clearVerifiedSignatureMemo()
      const normal = await verifyToken({ token: input })
      expect(yieldSpy).toHaveBeenCalledTimes(1)
      expect(disabled).toEqual(normal)
      for (const policy of [{ yield: false }, {}]) {
        yieldSpy.mockClear()
        const invalid = { ...token, signature: toB64U(new Uint8Array(64)) }
        await expect(
          verifyToken({
            token: serialized ? `${invalid.data}.${invalid.signature}` : invalid,
            ...policy,
          }),
        ).rejects.toThrow('Invalid signature')
        expect(yieldSpy).toHaveBeenCalledTimes(policy.yield === false ? 0 : 1)
      }
    })
  }
}

test('raw payload and verifier entry points accept the yield policy', async () => {
  const identity = createSigningIdentity({ privateKey })
  const token = await identity.signToken({ payload: { action: 'write' } })
  const input = {
    signature: fromB64U(token.signature),
    data: token.data,
    header: token.header,
    payload: token.payload,
  }
  yieldSpy.mockClear()
  expect(await verifySignedPayload({ ...input, yield: false })).toEqual(identity.publicKey)
  expect(yieldSpy).not.toHaveBeenCalled()
  clearVerifiedSignatureMemo()
  expect(
    await getVerifier({ algorithm: 'EdDSA', yield: false })({
      signature: input.signature,
      message: fromUTF(input.data),
      publicKey: identity.publicKey,
    }),
  ).toBe(true)
  expect(yieldSpy).not.toHaveBeenCalled()
  clearVerifiedSignatureMemo()
  await verifySignedPayload(input)
  expect(yieldSpy).toHaveBeenCalledTimes(1)
})

for (const serialized of [false, true]) {
  for (const disabledFirst of [false, true]) {
    test(`same-signature ${serialized ? 'serialized' : 'object'} verification stays independent, disabled first: ${disabledFirst}`, async () => {
      const identity = createSigningIdentity({ privateKey })
      const token = await identity.signToken({ payload: { action: 'write' }, yield: false })
      const input = serialized ? `${token.data}.${token.signature}` : token
      const { promise: gate, resolve: release } = Promise.withResolvers<void>()
      const { promise: entered, resolve: enter } = Promise.withResolvers<void>()
      yieldSpy.mockImplementationOnce(() => {
        enter()
        return gate
      })
      let normalFinished = false
      const startNormal = () => {
        return verifyToken({ token: input }).then((result) => {
          normalFinished = true
          return result
        })
      }
      const startDisabled = () => verifyToken({ token: input, yield: false })
      const first = disabledFirst ? startDisabled() : startNormal()
      const second = disabledFirst ? startNormal() : startDisabled()
      const normal = disabledFirst ? second : first
      const disabled = disabledFirst ? first : second
      try {
        await entered
        expect(await disabled).toMatchObject({ ...token, verifiedPublicKey: identity.publicKey })
        expect(normalFinished).toBe(false)
      } finally {
        release()
        await Promise.all([normal, disabled])
      }
      expect(normalFinished).toBe(true)
      expect(yieldSpy).toHaveBeenCalledTimes(1)
    })
  }
}

for (const policy of [{ yield: false }, {}]) {
  test(`issuer and signing-key checks remain active with yield ${policy.yield}`, async () => {
    const identity = createSigningIdentity({ privateKey })
    await expect(
      identity.signToken({
        payload: { iss: 'did:key:wrong' },
        ...policy,
      }),
    ).rejects.toThrow('Invalid payload: issuer does not match signer')
    const peer = await factories.peer()
    await expect(peer.signToken({ payload: {}, kid: '#absent', ...policy })).rejects.toThrow(
      'KidNotFound',
    )
    const token = await identity.signToken({ payload: {} })
    const wrong = createSigningIdentity({ privateKey: new Uint8Array(32).fill(8) })
    const payload = { ...token.payload, iss: wrong.id }
    const data = `${b64uFromJSON(token.header)}.${b64uFromJSON(payload)}`
    await expect(verifyToken({ token: { ...token, payload, data }, ...policy })).rejects.toThrow(
      'Invalid signature',
    )
  })
}

for (const policy of [{ yield: false }, { yield: true }, {}]) {
  test(`memo hits preserve time and audience checks with yield ${policy.yield}`, async () => {
    const identity = createSigningIdentity({ privateKey })
    const token = await identity.signToken({ payload: { aud: identity.id, exp: 200 } })
    yieldSpy.mockClear()
    const verified = await verifyToken({ token, atTime: 100, ...policy })
    expect(yieldSpy).toHaveBeenCalledTimes(policy.yield === false ? 0 : 1)
    yieldSpy.mockClear()
    expect(await verifyToken({ token, atTime: 100, ...policy })).toEqual(verified)
    expect(await verifyToken({ token: verified, atTime: 100, ...policy })).toBe(verified)
    await expect(verifyToken({ token: verified, atTime: 201, ...policy })).rejects.toThrow(
      'Token expired',
    )
    await expect(
      verifyToken({ token: verified, atTime: 100, audience: 'did:key:other', ...policy }),
    ).rejects.toThrow('audience')
    expect(yieldSpy).not.toHaveBeenCalled()
  })
}
