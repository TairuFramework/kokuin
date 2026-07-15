import type { FullIdentity, IdentityProvider } from '@kokuin/token'

import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'
import { CLA, INS } from '../src/apdu.js'
import { createLedgerIdentityProvider } from '../src/provider.js'
import type { LedgerTransport } from '../src/types.js'

// Fixed test private key (simulates what's on the Ledger at a given path)
const TEST_PRIVATE_KEY = ed25519.utils.randomSecretKey()
const TEST_PUBLIC_KEY = ed25519.getPublicKey(TEST_PRIVATE_KEY)

function createMockTransport(): LedgerTransport {
  let messageBuffer = new Uint8Array(0)

  return {
    async send(cla: number, ins: number, p1: number, _p2: number, data?: Uint8Array) {
      if (cla !== CLA) throw new Error(`Unknown CLA: ${cla}`)

      switch (ins) {
        case INS.GET_PUBLIC_KEY:
          return TEST_PUBLIC_KEY

        case INS.SIGN_MESSAGE: {
          if (p1 === 0x00) {
            const pathLen = 1 + (data?.[0] ?? 0) * 4
            messageBuffer = data?.slice(pathLen) ?? new Uint8Array(0)
          } else {
            const combined = new Uint8Array(messageBuffer.length + (data?.length ?? 0))
            combined.set(messageBuffer)
            if (data != null) combined.set(data, messageBuffer.length)
            messageBuffer = combined
          }
          return ed25519.sign(messageBuffer, TEST_PRIVATE_KEY)
        }

        case INS.ECDH_X25519: {
          const pathLen = 1 + (data?.[0] ?? 0) * 4
          const ephPub = data?.slice(pathLen)
          if (ephPub == null) throw new Error('Missing ephemeral public key')
          const x25519Private = ed25519.utils.toMontgomerySecret(TEST_PRIVATE_KEY)
          return x25519.getSharedSecret(x25519Private, ephPub)
        }

        default:
          throw new Error(`Unknown INS: ${ins}`)
      }
    },
  }
}

describe('ledger implements IdentityProvider and neither storage type', () => {
  test('conforms to IdentityProvider structurally', () => {
    // A compile-time assertion: if the return type ever stops satisfying IdentityProvider,
    // test:types fails. The runtime check below is the belt to that suspenders.
    const provider: IdentityProvider<FullIdentity> = createLedgerIdentityProvider(
      createMockTransport(),
    )
    expect(typeof provider.provideIdentity).toBe('function')
  })

  test('exposes no KeyStore or KeyEntry surface — the key never leaves the device', () => {
    const provider = createLedgerIdentityProvider(createMockTransport()) as Record<string, unknown>

    // This is the contract working, not an omission. There is no key material to get, set,
    // or remove: the private key is generated on-device and never leaves it. Under the old
    // contract this backend would have had to "conform" by throwing from setAsync — which is
    // exactly the lie the faceted contract exists to remove.
    expect(provider.entry).toBeUndefined()
    expect(provider.getAsync).toBeUndefined()
    expect(provider.setAsync).toBeUndefined()
    expect(provider.provideAsync).toBeUndefined()
    expect(provider.removeAsync).toBeUndefined()
  })

  test('provideIdentity yields a did:key EdDSA FullIdentity', async () => {
    const provider = createLedgerIdentityProvider(createMockTransport())
    const identity = await provider.provideIdentity('0')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(typeof identity.signToken).toBe('function')
    expect(typeof identity.decrypt).toBe('function')
    expect(typeof identity.agreeKey).toBe('function')
  })
})
