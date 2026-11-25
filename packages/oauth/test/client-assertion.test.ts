import { fromB64U, fromUTF, toB64U, toUTF } from '@sozai/codec'
import { describe, expect, test } from 'vitest'

import {
  CLIENT_ASSERTION_TYPE,
  type ClientAssertionAlgorithm,
  createClientAssertion,
  createWebCryptoAssertionSigner,
} from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

type Keys = { publicKey: CryptoKey; privateKey: CryptoKey }

async function generateKeys(alg: ClientAssertionAlgorithm): Promise<Keys> {
  const algorithm = alg === 'EdDSA' ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' }
  return (await crypto.subtle.generateKey(algorithm, false, ['sign', 'verify'])) as Keys
}

function decode(jws: string) {
  const [header, payload, signature] = jws.split('.') as [string, string, string]
  return {
    header: JSON.parse(toUTF(fromB64U(header))),
    claims: JSON.parse(toUTF(fromB64U(payload))),
    signingInput: `${header}.${payload}`,
    signature: fromB64U(signature),
  }
}

async function assertion(
  alg: ClientAssertionAlgorithm,
  kid: string | undefined,
  extra: { lifetimeSeconds?: number; typ?: string } = {},
) {
  const keys = await generateKeys(alg)
  const signer = createWebCryptoAssertionSigner({ alg, privateKey: keys.privateKey, kid })
  const jws = await createClientAssertion({
    signer,
    clientID: 'client-a',
    audience: 'https://as.example.com',
    now: () => 1000,
    ...extra,
  })
  return { jws, keys }
}

describe('createClientAssertion()', () => {
  test('exports the assertion type', () => {
    expect(CLIENT_ASSERTION_TYPE).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
  })

  test('header and claims', async () => {
    const { jws } = await assertion('EdDSA', 'k1')
    const { header, claims } = decode(jws)
    expect(header).toEqual({ alg: 'EdDSA', typ: 'client-authentication+jwt', kid: 'k1' })
    expect(claims.iss).toBe('client-a')
    expect(claims.sub).toBe('client-a')
    expect(claims.aud).toBe('https://as.example.com')
    expect(claims.exp - claims.iat).toBe(60)
    expect(claims.iat).toBe(1000)
    expect(typeof claims.jti).toBe('string')
    expect(claims.jti.length).toBeGreaterThan(0)
  })

  test('typ override', async () => {
    const { jws } = await assertion('EdDSA', undefined, { typ: 'JWT' })
    const { header } = decode(jws)
    expect(header.typ).toBe('JWT')
    expect('kid' in header).toBe(false)
  })

  test('lifetime', async () => {
    const { jws } = await assertion('EdDSA', 'k1', { lifetimeSeconds: 120 })
    const { claims } = decode(jws)
    expect(claims.exp - claims.iat).toBe(120)
  })

  test('verifies EdDSA', async () => {
    const { jws, keys } = await assertion('EdDSA', 'k1')
    const { signingInput, signature } = decode(jws)
    const ok = await crypto.subtle.verify(
      { name: 'Ed25519' },
      keys.publicKey,
      signature as Uint8Array<ArrayBuffer>,
      fromUTF(signingInput) as Uint8Array<ArrayBuffer>,
    )
    expect(ok).toBe(true)
  })

  test('verifies ES256', async () => {
    const { jws, keys } = await assertion('ES256', 'k1')
    const { signingInput, signature } = decode(jws)
    expect(signature).toHaveLength(64)
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      keys.publicKey,
      signature as Uint8Array<ArrayBuffer>,
      fromUTF(signingInput) as Uint8Array<ArrayBuffer>,
    )
    expect(ok).toBe(true)
  })

  test('fresh jti', async () => {
    const keys = await generateKeys('EdDSA')
    const signer = createWebCryptoAssertionSigner({ alg: 'EdDSA', privateKey: keys.privateKey })
    const params = { signer, clientID: 'client-a', audience: 'https://as.example.com' }
    const a = decode(await createClientAssertion(params))
    const b = decode(await createClientAssertion(params))
    expect(a.claims.jti).not.toBe(b.claims.jti)
  })

  test('uses runtime randomness for jti', async () => {
    const keys = await generateKeys('EdDSA')
    const signer = createWebCryptoAssertionSigner({ alg: 'EdDSA', privateKey: keys.privateKey })
    const jws = await createClientAssertion({
      signer,
      clientID: 'client-a',
      audience: 'https://as.example.com',
      runtime: fakeRuntime(),
    })
    const expected = toB64U(Uint8Array.from({ length: 16 }, (_, i) => i + 1))
    expect(decode(jws).claims.jti).toBe(expected)
  })

  test.each(['none', 'RS256'])('rejects unsupported alg %s', async (alg) => {
    const signer = { alg: alg as ClientAssertionAlgorithm, sign: async () => new Uint8Array(1) }
    await expect(
      createClientAssertion({ signer, clientID: 'c', audience: 'https://as.example.com' }),
    ).rejects.toThrow(`Unsupported client assertion algorithm: ${alg}`)
  })
})

describe('createWebCryptoAssertionSigner()', () => {
  test.each(['none', 'RS256'])('rejects unsupported alg %s', async (alg) => {
    const keys = await generateKeys('ES256')
    expect(() =>
      createWebCryptoAssertionSigner({
        alg: alg as ClientAssertionAlgorithm,
        privateKey: keys.privateKey,
      }),
    ).toThrow(`Unsupported client assertion algorithm: ${alg}`)
  })
})
