import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { isFullIdentity, verifyToken } from '@kokuin/token'
import { describe, expect, test, vi } from 'vitest'

import { HDKeyStore } from '../src/store.js'

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

describe('HDKeyStore as IdentityProvider', () => {
  test('provideIdentity() returns FullIdentity', async () => {
    const store = HDKeyStore.fromMnemonic({ mnemonic: MNEMONIC })
    const identity = await store.provideIdentity('0')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(isFullIdentity(identity)).toBe(true)
  })

  test('same keyID produces same DID', async () => {
    const store = HDKeyStore.fromMnemonic({ mnemonic: MNEMONIC })
    const a = await store.provideIdentity('0')
    const b = await store.provideIdentity('0')
    expect(a.id).toBe(b.id)
  })

  test('different keyID produces different DID', async () => {
    const store = HDKeyStore.fromMnemonic({ mnemonic: MNEMONIC })
    const a = await store.provideIdentity('0')
    const b = await store.provideIdentity('1')
    expect(a.id).not.toBe(b.id)
  })

  test('identity can sign and verify tokens', async () => {
    const store = HDKeyStore.fromMnemonic({ mnemonic: MNEMONIC })
    const identity = await store.provideIdentity('0')
    const token = await identity.signToken({ payload: { data: 'test' } })
    expect(token.payload.iss).toBe(identity.id)
    const verified = await verifyToken({ token: `${token.data}.${token.signature}` })
    expect(verified.payload.data).toBe('test')
  })

  test('identity can perform ECDH key agreement', async () => {
    const store = HDKeyStore.fromMnemonic({ mnemonic: MNEMONIC })
    const identity = await store.provideIdentity('0')
    const { x25519 } = await import('@noble/curves/ed25519.js')
    const ephPriv = x25519.utils.randomSecretKey()
    const ephPub = x25519.getPublicKey(ephPriv)
    const shared = await identity.agreeKey({ ephemeralPublicKey: ephPub })
    expect(shared).toBeInstanceOf(Uint8Array)
    expect(shared.length).toBe(32)
  })

  test('same mnemonic produces same identity', async () => {
    const a = HDKeyStore.fromMnemonic({ mnemonic: MNEMONIC })
    const b = HDKeyStore.fromMnemonic({ mnemonic: MNEMONIC })
    const idA = await a.provideIdentity('0')
    const idB = await b.provideIdentity('0')
    expect(idA.id).toBe(idB.id)
  })
})

test('all deterministic factories capture the signing provider', async () => {
  const sign = vi.fn(nobleCrypto.sign)
  const crypto = { ...nobleCrypto, sign }
  const options: { crypto: CryptoProvider } = { crypto }
  const stores = [
    new HDKeyStore({ seed: new Uint8Array(32).fill(1), crypto }),
    HDKeyStore.fromSeed({ seed: new Uint8Array(32).fill(1), ...options }),
    HDKeyStore.fromMnemonic({ mnemonic: MNEMONIC, ...options }),
  ]
  options.crypto = { ...nobleCrypto }
  for (const store of stores)
    await (await store.provideIdentity('0')).signToken({ payload: { value: 1 } })
  expect(sign).toHaveBeenCalledTimes(3)
})
