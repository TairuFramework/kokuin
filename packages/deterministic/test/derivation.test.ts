import { describe, expect, test } from 'vitest'

import { derivePrivateKey, resolveDerivationPath } from '../src/derivation.js'

const DEFAULT_BASE_PATH = "44'/876'"

describe('resolveDerivationPath()', () => {
  test('resolves numeric index to full path', () => {
    expect(resolveDerivationPath('0', DEFAULT_BASE_PATH)).toBe("m/44'/876'/0'")
  })

  test('resolves string index to full hardened path', () => {
    expect(resolveDerivationPath('5', DEFAULT_BASE_PATH)).toBe("m/44'/876'/5'")
  })

  test('passes through full path unchanged', () => {
    expect(resolveDerivationPath("m/44'/876'/2'", DEFAULT_BASE_PATH)).toBe("m/44'/876'/2'")
  })

  test('throws for invalid keyID', () => {
    expect(() => resolveDerivationPath('abc', DEFAULT_BASE_PATH)).toThrow()
  })

  test('rejects a non-hardened segment — SLIP-0010 ed25519 has no public derivation', () => {
    expect(() => resolveDerivationPath("m/44'/876/0'")).toThrow(/hardened/)
    expect(() => resolveDerivationPath("m/44'/876'/0")).toThrow(/hardened/)
    expect(() => resolveDerivationPath('m/0')).toThrow(/hardened/)
  })

  test('accepts hardened segments with either notation', () => {
    expect(resolveDerivationPath("m/44'/876'/0'")).toBe("m/44'/876'/0'")
    expect(resolveDerivationPath('m/44h/876h/0h')).toBe('m/44h/876h/0h')
  })

  test('accepts the bare master path', () => {
    expect(resolveDerivationPath('m')).toBe('m')
  })
})

describe('derivePrivateKey()', () => {
  // SLIP-0010 test vector from https://github.com/satoshilabs/slips/blob/master/slip-0010.md
  // Test Vector 1 for ed25519
  const seed = Uint8Array.from(
    ('000102030405060708090a0b0c0d0e0f'.match(/.{2}/g) ?? []).map((b) => Number.parseInt(b, 16)),
  )

  test('derives master key from seed', () => {
    const key = derivePrivateKey(seed, 'm')
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
  })

  test('derives child key at path', () => {
    const key = derivePrivateKey(seed, "m/0'")
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
  })

  test('same seed + path produces same key', () => {
    const a = derivePrivateKey(seed, "m/44'/876'/0'")
    const b = derivePrivateKey(seed, "m/44'/876'/0'")
    expect(a).toEqual(b)
  })

  test('different paths produce different keys', () => {
    const a = derivePrivateKey(seed, "m/44'/876'/0'")
    const b = derivePrivateKey(seed, "m/44'/876'/1'")
    expect(a).not.toEqual(b)
  })
})
