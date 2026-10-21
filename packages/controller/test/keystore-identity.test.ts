import { HDKeyStore } from '@kokuin/deterministic'
import { createTokenEncrypter, decryptToken, encryptToken } from '@kokuin/jwe'
import type { KeyEntry } from '@kokuin/token'
import { isFullIdentity } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { agreementPath, deriveKeyPair } from '../src/derivation.js'
import { createInception, createRevoke, createRotate, didFromInception } from '../src/events.js'
import { createMemoryLogStore } from '../src/history.js'
import { provideControllerIdentity } from '../src/keystore-identity.js'

// A minimal raw-byte KeyEntry: provideAsync generates once and restores thereafter — the contract
// node/electron/expo/deterministic satisfy. `seed` lets a test pin the bytes.
function memoryEntry(seed?: Uint8Array): KeyEntry<Uint8Array> {
  let stored = seed
  return {
    keyID: 'test',
    async getAsync() {
      return stored ?? null
    },
    async provideAsync() {
      stored ??= new Uint8Array(32).fill(7)
      return stored
    },
  }
}

describe('provideControllerIdentity', () => {
  test('generates a fresh identity when the log store is empty', async () => {
    const seed = new Uint8Array(32).fill(7)
    const logStore = createMemoryLogStore()
    const identity = await provideControllerIdentity({
      entry: memoryEntry(seed),
      profile: 0,
      logStore,
    })

    const expectedDID = didFromInception(createInception(seed, 0).event)
    expect(identity.id).toBe(expectedDID)
    expect(isFullIdentity(identity)).toBe(true)
    // The generate path persisted the inception.
    const stored = await logStore.get(expectedDID)
    expect(stored).toHaveLength(1)
  })

  test('restores the same identity from an existing log', async () => {
    const seed = new Uint8Array(32).fill(7)
    const logStore = createMemoryLogStore()
    const first = await provideControllerIdentity({
      entry: memoryEntry(seed),
      profile: 0,
      logStore,
    })
    const second = await provideControllerIdentity({
      entry: memoryEntry(seed),
      profile: 0,
      logStore,
    })
    expect(second.id).toBe(first.id)
  })

  test('a different profile under the same seed is a different DID', async () => {
    const seed = new Uint8Array(32).fill(7)
    const logStore = createMemoryLogStore()
    const a = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 0, logStore })
    const b = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 1, logStore })
    expect(a.id).not.toBe(b.id)
  })

  test('resolves the current key after a rotate', async () => {
    const seed = new Uint8Array(32).fill(7)
    const logStore = createMemoryLogStore()
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rot = createRotate({ seed, profile: 0, did, prior: inception.event })
    await logStore.set(did, [inception, rot])

    const identity = await provideControllerIdentity({
      entry: memoryEntry(seed),
      profile: 0,
      logStore,
    })
    expect(identity.id).toBe(did)
    const token = await identity.signToken({ sub: 'x' })
    // After a rotate the authority key is the rotate's revealed key, so the kid names it.
    expect(token.header.kid).toBe(`#${rot.event.k[0]}`)
  })

  test('resolves the pre-revoke key after a revoke', async () => {
    const seed = new Uint8Array(32).fill(7)
    const logStore = createMemoryLogStore()
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const revoke = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      keyPosition: { gen: 0, seq: 0 },
    })
    await logStore.set(did, [inception, revoke])

    const identity = await provideControllerIdentity({
      entry: memoryEntry(seed),
      profile: 0,
      logStore,
    })
    expect(identity.id).toBe(did)
    const token = await identity.signToken({ sub: 'x' })
    // The revoke established no key, so the authority key is still the inception's.
    expect(token.header.kid).toBe(`#${inception.event.k[0]}`)
  })
})

test('the resolved FullIdentity decrypts a JWE encrypted to its agreement key', async () => {
  const seed = new Uint8Array(32).fill(7)
  const logStore = createMemoryLogStore()
  const identity = await provideControllerIdentity({
    entry: memoryEntry(seed),
    profile: 0,
    logStore,
  })

  // The agreement key at the inception position (gen 0, seq 0) is the current one for a fresh log.
  const agreementPublicKey = deriveKeyPair(seed, agreementPath(0, 0, 0), 'X25519').publicKey
  const encrypter = createTokenEncrypter(agreementPublicKey, { algorithm: 'X25519' })
  const plaintext = new TextEncoder().encode('sealed to the controller')
  const jwe = await encryptToken(encrypter, plaintext)

  const decrypted = await decryptToken(identity, jwe)
  expect(decrypted).toEqual(plaintext)
})

test('drives end to end from a real @kokuin/deterministic KeyStore', async () => {
  // mnemonicToSeedSync runs PBKDF2 over the phrase without checking a BIP39 checksum, so this
  // placeholder phrase derives fine; the entry hands back raw bytes the utility uses as seed.
  const keyStore = HDKeyStore.fromMnemonic(
    'test test test test test test test test test test test junk',
  )
  const logStore = createMemoryLogStore()

  const identity = await provideControllerIdentity({
    entry: keyStore.entry('0'),
    profile: 0,
    logStore,
  })

  expect(identity.id.startsWith('did:kokuin:')).toBe(true)
  expect(isFullIdentity(identity)).toBe(true)

  // Restore returns the same identity.
  const again = await provideControllerIdentity({
    entry: keyStore.entry('0'),
    profile: 0,
    logStore,
  })
  expect(again.id).toBe(identity.id)
})
