import { ed25519 } from '@noble/curves/ed25519.js'
import { b64uFromJSON, fromUTF, toB64U } from '@sozai/codec'
import { equals } from 'uint8arrays'
import { describe, expect, it, test } from 'vitest'

import { createIdentity, randomIdentity } from '../src/identity.js'
import {
  createUnsignedToken,
  isSignedToken,
  isUnsignedToken,
  isVerifiedToken,
  signToken,
  verifyToken,
} from '../src/token.js'
import type { VerifiedToken } from '../src/types.js'
import { stringifyToken } from '../src/utils.js'

test('create a signed token and verify it', async () => {
  const identity = randomIdentity()
  const token = await identity.signToken({ test: true })
  expect(isSignedToken(token)).toBe(true)
  expect(token.payload.iss).toBe(identity.id)
  const verified = await verifyToken(token)
  expect(isVerifiedToken(verified)).toBe(true)
  const publicKey = ed25519.getPublicKey(identity.privateKey)
  expect(equals((verified as VerifiedToken<{ test: true }>).verifiedPublicKey, publicKey)).toBe(
    true,
  )
})

test('verifyToken rejects malformed JWT strings', async () => {
  // Too few parts
  await expect(verifyToken('header.payload')).rejects.toThrow('Invalid token format')
  await expect(verifyToken('header')).rejects.toThrow('Invalid token format')
  await expect(verifyToken('')).rejects.toThrow('Invalid token format')

  // Too many parts
  await expect(verifyToken('a.b.c.d')).rejects.toThrow('Invalid token format')
  await expect(verifyToken('a.b.c.d.e')).rejects.toThrow('Invalid token format')
})

test('create an unsigned token, sign and stringify it', async () => {
  const unsigned = createUnsignedToken({ test: true })
  expect(isUnsignedToken(unsigned)).toBe(true)
  const identity = randomIdentity()
  const signed = await signToken(identity, unsigned)
  expect(isSignedToken(signed)).toBe(true)
  const stringified = stringifyToken(signed)
  const verified = await verifyToken(stringified)
  expect(isVerifiedToken(verified)).toBe(true)
})

describe('verifyToken with time validation', () => {
  const fixedTime = 1700000000

  test('rejects expired signed token', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({
      test: true,
      exp: fixedTime - 100,
    })

    await expect(verifyToken(token, { atTime: fixedTime })).rejects.toThrow('Token expired')
  })

  test('rejects token not yet valid (nbf in future)', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({
      test: true,
      nbf: fixedTime + 100,
    })

    await expect(verifyToken(token, { atTime: fixedTime })).rejects.toThrow('Token not yet valid')
  })

  test('accepts token within valid time window', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({
      test: true,
      nbf: fixedTime - 100,
      exp: fixedTime + 100,
    })

    const result = await verifyToken(token, { atTime: fixedTime })
    expect(result.payload.test).toBe(true)
  })

  test('accepts token without time claims', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({ test: true })

    const result = await verifyToken(token, { atTime: fixedTime })
    expect(result.payload.test).toBe(true)
  })

  test('respects clockTolerance option', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({
      test: true,
      exp: fixedTime - 5,
    })

    await expect(verifyToken(token, { atTime: fixedTime })).rejects.toThrow('Token expired')

    const result = await verifyToken(token, { atTime: fixedTime, clockTolerance: 10 })
    expect(result.payload.test).toBe(true)
  })

  test('validates time claims for JWT string tokens', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({
      test: true,
      exp: fixedTime - 100,
    })
    const tokenString = stringifyToken(token)

    await expect(verifyToken(tokenString, { atTime: fixedTime })).rejects.toThrow('Token expired')
  })
})

test('verifyToken uses generic error for invalid header type', async () => {
  const identity = randomIdentity()
  const token = await identity.signToken({ test: true })
  const str = stringifyToken(token)
  const [, payload, sig] = str.split('.')
  const badHeader = b64uFromJSON({ typ: 'NOT_JWT', alg: 'EdDSA' })
  await expect(verifyToken(`${badHeader}.${payload}.${sig}`)).rejects.toThrow(
    'Invalid token header type',
  )
})

test('verifyToken uses generic error for unsupported algorithm', async () => {
  const identity = randomIdentity()
  const token = await identity.signToken({ test: true })
  const str = stringifyToken(token)
  const [, payload, sig] = str.split('.')
  const badHeader = b64uFromJSON({ typ: 'JWT', alg: 'RS256' })
  await expect(verifyToken(`${badHeader}.${payload}.${sig}`)).rejects.toThrow(
    'Unsupported signature algorithm',
  )
})

describe('object token signature/payload binding', () => {
  test('rejects object tokens whose data does not match the payload', async () => {
    const victim = randomIdentity()
    const attacker = randomIdentity()
    // any token signed by the victim, e.g. a capability delegated to the attacker
    const original = await victim.signToken({ aud: attacker.id, cap: 'kv/read' })
    // attacker reuses the victim's signature with an arbitrary payload
    const forged = {
      header: original.header,
      payload: { iss: victim.id, aud: attacker.id, cap: 'kv/admin' },
      signature: original.signature,
      data: original.data,
    }
    await expect(verifyToken(forged)).rejects.toThrow('data does not match')
  })

  test('verifies object tokens after JSON round-trip', async () => {
    const identity = randomIdentity()
    const signed = await identity.signToken({ test: 1, nested: { b: 2, a: 1 } })
    const wire = JSON.parse(JSON.stringify(signed))
    const verified = await verifyToken(wire)
    expect(isVerifiedToken(verified)).toBe(true)
  })

  test('verifies object tokens without a data field', async () => {
    const identity = randomIdentity()
    const signed = await identity.signToken({ test: true })
    const { data: _data, ...withoutData } = signed
    const verified = await verifyToken(withoutData as typeof signed)
    expect(isVerifiedToken(verified)).toBe(true)
  })

  test('accepts data using a different serialization of the same payload', async () => {
    const identity = randomIdentity()
    const header = { typ: 'JWT', alg: 'EdDSA' }
    // non-canonical key order: JSON.stringify preserves insertion order (iss, b, a)
    const payload = { iss: identity.id, b: 2, a: 1 }
    const data = `${b64uFromJSON(header, false)}.${b64uFromJSON(payload, false)}`
    const signature = toB64U(ed25519.sign(fromUTF(data), identity.privateKey))
    const token = { header, payload, signature, data }
    const verified = await verifyToken(token as Parameters<typeof verifyToken>[0])
    expect(isVerifiedToken(verified)).toBe(true)
  })

  test('rejects object tokens whose data is not a string', async () => {
    const identity = randomIdentity()
    const signed = await identity.signToken({ test: true })
    const forged = { ...signed, data: { malicious: true } }
    await expect(
      verifyToken(forged as unknown as Parameters<typeof verifyToken>[0]),
    ).rejects.toThrow('data does not match')
  })
})

describe('verified token branding', () => {
  test('isVerifiedToken rejects deserialized tokens carrying verifiedPublicKey', async () => {
    const identity = randomIdentity()
    const signed = await identity.signToken({ test: true })
    const verified = await verifyToken(signed)
    expect(isVerifiedToken(verified)).toBe(true)
    // round-trip through JSON, as a wire message would arrive
    const wire = JSON.parse(JSON.stringify(verified))
    expect(isVerifiedToken(wire)).toBe(false)
  })

  test('verifyToken re-verifies tokens carrying an inbound verifiedPublicKey', async () => {
    const victim = randomIdentity()
    const signed = await victim.signToken({ test: true })
    // forged payload, victim signature, attacker-injected verifiedPublicKey
    const forged = {
      header: signed.header,
      payload: { ...signed.payload, admin: true },
      signature: signed.signature,
      data: signed.data,
      verifiedPublicKey: new Uint8Array(32),
    }
    await expect(verifyToken(forged)).rejects.toThrow()
  })

  test('deserialized token with verifiedPublicKey still verifies when genuine', async () => {
    const identity = randomIdentity()
    const verified = await verifyToken(await identity.signToken({ test: true }))
    const wire = JSON.parse(JSON.stringify(verified))
    const reverified = await verifyToken(wire)
    expect(isVerifiedToken(reverified)).toBe(true)
  })
})

describe('verifyToken with cache', () => {
  it('populates cache when iss is peer4 long form and signature is valid', async () => {
    const identity = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const { createInMemoryDIDCache } = await import('../src/cache.js')
    const { encodePeer4 } = await import('../src/peer4.js')
    const cache = createInMemoryDIDCache()
    const { ed25519: ed } = await import('@noble/curves/ed25519.js')
    const { b64uFromJSON: b64uJSON, fromUTF: fUTF, toB64U: tb64u } = await import('@sozai/codec')
    const key = identity.keys[0]
    const header = { typ: 'JWT' as const, alg: 'EdDSA' as const, kid: key.fragment }
    const payload = { iss: identity.longForm, sub: identity.id, aud: 'someone' }
    const data = `${b64uJSON(header)}.${b64uJSON(payload)}`
    const signature = tb64u(ed.sign(fUTF(data), key.privateKey))
    const token = { header, payload, signature, data }
    await verifyToken(token, { cache })
    const { shortForm } = encodePeer4(identity.doc)
    expect(await cache.get(shortForm)).toEqual(identity.doc)
  })

  it('does NOT populate cache when signature is invalid', async () => {
    const identity = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const { createInMemoryDIDCache } = await import('../src/cache.js')
    const { encodePeer4 } = await import('../src/peer4.js')
    const cache = createInMemoryDIDCache()
    const { ed25519: ed } = await import('@noble/curves/ed25519.js')
    const { b64uFromJSON: b64uJSON, fromUTF: fUTF, toB64U: tb64u } = await import('@sozai/codec')
    const key = identity.keys[0]
    const header = { typ: 'JWT' as const, alg: 'EdDSA' as const, kid: key.fragment }
    const payload = { iss: identity.longForm, sub: identity.id, aud: 'someone' }
    const data = `${b64uJSON(header)}.${b64uJSON(payload)}`
    const goodSig = ed.sign(fUTF(data), key.privateKey)
    void goodSig
    const tamperedBytes = new Uint8Array(64)
    tamperedBytes[0] = 1
    const bad = { header, payload, signature: tb64u(tamperedBytes), data }
    await expect(verifyToken(bad, { cache })).rejects.toThrow(/Invalid signature/)
    const { shortForm } = encodePeer4(identity.doc)
    expect(await cache.get(shortForm)).toBeUndefined()
  })

  it('verifies short-form iss against pre-populated cache', async () => {
    const identity = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const { createInMemoryDIDCache } = await import('../src/cache.js')
    const { encodePeer4 } = await import('../src/peer4.js')
    const cache = createInMemoryDIDCache()
    const { shortForm } = encodePeer4(identity.doc)
    await cache.set(shortForm, identity.doc)
    const token = await identity.signToken({ sub: identity.id, aud: 'someone' })
    await expect(verifyToken(token, { cache })).resolves.toBeDefined()
  })

  it('falls through to resolver on cache miss', async () => {
    const identity = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const { createInMemoryDIDCache } = await import('../src/cache.js')
    const { encodePeer4 } = await import('../src/peer4.js')
    const cache = createInMemoryDIDCache()
    const { shortForm } = encodePeer4(identity.doc)
    let resolverHits = 0
    const resolver = (did: string) => {
      resolverHits++
      return did === shortForm ? identity.doc : undefined
    }
    const token = await identity.signToken(
      { sub: identity.id, aud: 'someone' },
      { embedLongForm: false },
    )
    await verifyToken(token, { cache, resolver })
    expect(resolverHits).toBe(1)
    const token2 = await identity.signToken(
      { sub: identity.id, aud: 'someone-else' },
      { embedLongForm: false },
    )
    await verifyToken(token2, { cache, resolver })
    expect(resolverHits).toBe(1)
  })
})

describe('type guards are total', () => {
  const nonTokens = [null, undefined, '', 0, false, [], 'string', {}]

  for (const value of nonTokens) {
    it(`isSignedToken returns false for ${JSON.stringify(value) ?? 'undefined'}`, () => {
      expect(isSignedToken(value)).toBe(false)
    })

    it(`isUnsignedToken returns false for ${JSON.stringify(value) ?? 'undefined'}`, () => {
      expect(isUnsignedToken(value)).toBe(false)
    })

    it(`isVerifiedToken returns false for ${JSON.stringify(value) ?? 'undefined'}`, () => {
      expect(isVerifiedToken(value)).toBe(false)
    })
  }
})

describe('verifyToken rejects alg:none by default', () => {
  const fixedTime = 1700000000

  function unsignedString(payload: Record<string, unknown>, header = { typ: 'JWT', alg: 'none' }) {
    return `${b64uFromJSON(header)}.${b64uFromJSON(payload)}.`
  }

  it('rejects an alg:none token string', async () => {
    await expect(verifyToken(unsignedString({ test: true }))).rejects.toThrow(
      /unsigned tokens rejected/,
    )
  })

  it('rejects an unsigned token object', async () => {
    const unsigned = createUnsignedToken({ test: true })
    await expect(verifyToken(unsigned)).rejects.toThrow(/unsigned tokens rejected/)
  })

  it('accepts an alg:none token string with allowUnsigned', async () => {
    const token = await verifyToken(unsignedString({ test: true }), { allowUnsigned: true })
    expect(isUnsignedToken(token)).toBe(true)
    expect(token.payload).toEqual({ test: true })
  })

  it('accepts an unsigned token object with allowUnsigned', async () => {
    const unsigned = createUnsignedToken({ test: true })
    const token = await verifyToken(unsigned, { allowUnsigned: true })
    expect(token).toBe(unsigned)
  })

  it('rejects a malformed unsigned header even with allowUnsigned', async () => {
    const bad = unsignedString({ test: true }, { typ: 'NOTJWT', alg: 'none' })
    await expect(verifyToken(bad, { allowUnsigned: true })).rejects.toThrow(
      'Invalid token header type',
    )
  })

  it('rejects an expired unsigned token with allowUnsigned', async () => {
    const token = unsignedString({ test: true, exp: fixedTime - 100 })
    await expect(
      verifyToken(token, { allowUnsigned: true, atTime: fixedTime }),
    ).rejects.toThrow('Token expired')
  })

  it('rejects a not-yet-valid unsigned token with allowUnsigned', async () => {
    const token = unsignedString({ test: true, nbf: fixedTime + 100 })
    await expect(
      verifyToken(token, { allowUnsigned: true, atTime: fixedTime }),
    ).rejects.toThrow('Token not yet valid')
  })

  it('honours clockTolerance for an expired unsigned token', async () => {
    const token = unsignedString({ test: true, exp: fixedTime - 100 })
    await expect(
      verifyToken(token, { allowUnsigned: true, atTime: fixedTime, clockTolerance: 200 }),
    ).resolves.toBeDefined()
  })

  it('rejects an unsigned token when an audience is expected, even with allowUnsigned', async () => {
    const token = unsignedString({ test: true, aud: 'did:key:service-a' })
    await expect(
      verifyToken(token, { allowUnsigned: true, audience: 'did:key:service-a' }),
    ).rejects.toThrow(/requires a signed token/)
  })

  it('still verifies a signed token with no options', async () => {
    const identity = randomIdentity()
    const signed = await identity.signToken({ test: true })
    const verified = await verifyToken(stringifyToken(signed))
    expect(isVerifiedToken(verified)).toBe(true)
  })
})
