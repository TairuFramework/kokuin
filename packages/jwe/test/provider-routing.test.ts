import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { randomIdentity } from '@kokuin/token'
import { expect, test } from 'vitest'

import { createTokenEncrypter, unwrapEnvelope, wrapEnvelope } from '../src/index.js'

for (const mode of ['jws', 'jws-in-jwe', 'jwe-in-jws'] as const) {
  test(`${mode} verifies through the selected provider`, async () => {
    const sender = randomIdentity()
    const recipient = randomIdentity()
    const message = await wrapEnvelope({
      mode,
      payload: { value: mode },
      signer: sender,
      encrypter: createTokenEncrypter({ recipient: recipient.id }),
    })
    let calls = 0
    const crypto: CryptoProvider = {
      ...nobleCrypto,
      async verify(...args) {
        calls++
        return nobleCrypto.verify(...args)
      },
    }
    expect(await unwrapEnvelope({ message, decrypter: recipient, crypto })).toEqual({
      mode,
      payload: mode === 'jwe-in-jws' ? { value: mode } : { value: mode, iss: sender.id },
    })
    expect(calls).toBe(1)
    const rejecting: CryptoProvider = {
      ...nobleCrypto,
      async verify() {
        calls++
        return false
      },
    }
    await expect(
      unwrapEnvelope({ message, decrypter: recipient, crypto: rejecting }),
    ).rejects.toThrow('Invalid signature')
    const sentinel = new Error('verification offline')
    const failed: CryptoProvider = {
      ...nobleCrypto,
      async verify() {
        calls++
        throw sentinel
      },
    }
    for (let i = 0; i < 2; i++)
      await expect(unwrapEnvelope({ message, decrypter: recipient, crypto: failed })).rejects.toBe(
        sentinel,
      )
    expect(calls).toBe(4)
  })
}

test('plain envelopes never invoke the provider', async () => {
  const crypto: CryptoProvider = {
    ...nobleCrypto,
    async verify() {
      throw new Error('unexpected verification')
    },
  }
  const message = await wrapEnvelope({ mode: 'plain', payload: { value: 'plain' }, ...{} })
  expect(await unwrapEnvelope({ message, crypto })).toEqual({
    mode: 'plain',
    payload: { value: 'plain' },
  })
})
