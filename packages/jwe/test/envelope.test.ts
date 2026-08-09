import { randomIdentity } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createTokenEncrypter, unwrapEnvelope, wrapEnvelope } from '../src/index.js'

describe('wrapEnvelope / unwrapEnvelope', () => {
  test('plain mode round-trip', async () => {
    const payload = { typ: 'request', prc: 'test', rid: '123', prm: {} }
    const wrapped = await wrapEnvelope('plain', payload, {})
    const result = await unwrapEnvelope(wrapped, {})
    expect(result.mode).toBe('plain')
    expect(result.payload.typ).toBe('request')
  })

  test('plain mode rejects an expired envelope', async () => {
    const wrapped = await wrapEnvelope('plain', { test: true, exp: 1700000000 - 100 }, {})
    await expect(unwrapEnvelope(wrapped, {})).rejects.toThrow('Token expired')
  })

  test('jws mode round-trip', async () => {
    const identity = randomIdentity()
    const payload = { typ: 'request', prc: 'test', rid: '123', prm: {} }
    const wrapped = await wrapEnvelope('jws', payload, { signer: identity })
    const result = await unwrapEnvelope(wrapped, {})
    expect(result.mode).toBe('jws')
    expect(result.payload.prc).toBe('test')
  })

  test('jws-in-jwe mode round-trip', async () => {
    const sender = randomIdentity()
    const recipient = randomIdentity()
    const encrypter = createTokenEncrypter(recipient.id)
    const payload = { typ: 'request', prc: 'secret', rid: '456', prm: { key: 'value' } }

    const wrapped = await wrapEnvelope('jws-in-jwe', payload, {
      signer: sender,
      encrypter,
    })
    const result = await unwrapEnvelope(wrapped, { decrypter: recipient })
    expect(result.mode).toBe('jws-in-jwe')
    expect(result.payload.prc).toBe('secret')
  })

  test('jwe-in-jws mode round-trip', async () => {
    const sender = randomIdentity()
    const recipient = randomIdentity()
    const encrypter = createTokenEncrypter(recipient.id)
    const payload = { typ: 'request', prc: 'secret', rid: '789', prm: {} }

    const wrapped = await wrapEnvelope('jwe-in-jws', payload, {
      signer: sender,
      encrypter,
    })
    const result = await unwrapEnvelope(wrapped, { decrypter: recipient })
    expect(result.mode).toBe('jwe-in-jws')
    expect(result.payload.prc).toBe('secret')
  })

  test('wrapEnvelope throws if jws mode but no signer', async () => {
    const payload = { typ: 'request', prc: 'test', rid: '1' }
    await expect(wrapEnvelope('jws', payload, {})).rejects.toThrow('Signer required')
  })

  test('wrapEnvelope throws if encrypted mode but no encrypter', async () => {
    const identity = randomIdentity()
    const payload = { typ: 'request', prc: 'test', rid: '1' }
    await expect(wrapEnvelope('jws-in-jwe', payload, { signer: identity })).rejects.toThrow(
      'Encrypter required',
    )
  })

  test('wrapEnvelope throws if jwe-in-jws mode but no signer', async () => {
    const recipient = randomIdentity()
    const encrypter = createTokenEncrypter(recipient.id)
    const payload = { typ: 'request', prc: 'test', rid: '1' }
    await expect(wrapEnvelope('jwe-in-jws', payload, { encrypter })).rejects.toThrow(
      'Signer required',
    )
  })

  test('wrapEnvelope throws if jwe-in-jws mode but no encrypter', async () => {
    const identity = randomIdentity()
    const payload = { typ: 'request', prc: 'test', rid: '1' }
    await expect(wrapEnvelope('jwe-in-jws', payload, { signer: identity })).rejects.toThrow(
      'Encrypter required',
    )
  })

  test('wrapEnvelope throws if jws-in-jwe mode but no signer', async () => {
    const recipient = randomIdentity()
    const encrypter = createTokenEncrypter(recipient.id)
    const payload = { typ: 'request', prc: 'test', rid: '1' }
    await expect(wrapEnvelope('jws-in-jwe', payload, { encrypter })).rejects.toThrow(
      'Signer required',
    )
  })

  test('unwrapEnvelope throws for 5-part message without decrypter', async () => {
    await expect(unwrapEnvelope('a.b.c.d.e', {})).rejects.toThrow('Decrypter required')
  })

  test('unwrapEnvelope throws for invalid part count', async () => {
    await expect(unwrapEnvelope('a.b', {})).rejects.toThrow('Invalid envelope format')
    await expect(unwrapEnvelope('a.b.c.d', {})).rejects.toThrow('Invalid envelope format')
    await expect(unwrapEnvelope('a', {})).rejects.toThrow('Invalid envelope format')
  })
})
