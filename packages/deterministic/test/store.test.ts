import { describe, expect, test } from 'vitest'

import { derivePrivateKey } from '../src/derivation.js'
import { HDKeyEntry } from '../src/entry.js'
import { HDKeyStore } from '../src/store.js'

// Deterministic seed for testing
const SEED = Uint8Array.from(
  '000102030405060708090a0b0c0d0e0f'.match(/.{2}/g)?.map((b) => Number.parseInt(b, 16)) ?? [],
)

describe('HDKeyEntry', () => {
  test('keyID is the caller’s keyID, not the path', () => {
    const entry = new HDKeyEntry({ seed: SEED, keyID: '0', path: "m/44'/876'/0'" })
    expect(entry.keyID).toBe('0')
    expect(entry.path).toBe("m/44'/876'/0'")
  })

  test('getAsync() returns derived private key', async () => {
    const entry = new HDKeyEntry({ seed: SEED, keyID: '0', path: "m/44'/876'/0'" })
    const key = await entry.getAsync()
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key?.length).toBe(32)
    // Should match direct derivation
    expect(key).toEqual(derivePrivateKey(SEED, "m/44'/876'/0'"))
  })

  test('provideAsync() returns same key as getAsync()', async () => {
    const entry = new HDKeyEntry({ seed: SEED, keyID: '0', path: "m/44'/876'/0'" })
    const a = await entry.getAsync()
    const b = await entry.provideAsync()
    expect(a).toEqual(b)
  })
})

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

describe('HDKeyStore', () => {
  test('fromMnemonic() creates store', () => {
    const store = HDKeyStore.fromMnemonic(MNEMONIC)
    expect(store).toBeDefined()
  })

  test('fromSeed() creates store', () => {
    const seed = new Uint8Array(64)
    const store = HDKeyStore.fromSeed(seed)
    expect(store).toBeDefined()
  })

  test('entry() returns HDKeyEntry for index', async () => {
    const store = HDKeyStore.fromMnemonic(MNEMONIC)
    const entry = store.entry('0')
    expect(entry.keyID).toBe('0')
    expect(entry.path).toBe("m/44'/876'/0'")
    const key = await entry.provideAsync()
    expect(key.length).toBe(32)
  })

  test('entry() returns HDKeyEntry for full path', async () => {
    const store = HDKeyStore.fromMnemonic(MNEMONIC)
    const entry = store.entry("m/44'/876'/5'")
    expect(entry.keyID).toBe("m/44'/876'/5'")
  })

  test('same keyID returns same entry', () => {
    const store = HDKeyStore.fromMnemonic(MNEMONIC)
    const a = store.entry('0')
    const b = store.entry('0')
    expect(a).toBe(b)
  })

  test('index and full-path aliases of the same derivation are distinct entries with own keyID', async () => {
    const store = HDKeyStore.fromSeed(SEED)
    const byIndex = store.entry('0')
    const byPath = store.entry("m/44'/876'/0'")
    expect(byIndex).not.toBe(byPath)
    expect(byIndex.keyID).toBe('0')
    expect(byPath.keyID).toBe("m/44'/876'/0'")
    expect(byIndex.path).toBe(byPath.path)
    expect(await byIndex.provideAsync()).toEqual(await byPath.provideAsync())
  })
})
