import { describe, expect, test } from 'vitest'

import {
  agreementPath,
  authorityPath,
  deriveKeyMaterial,
  deriveKeyPair,
  recoveryPath,
} from '../src/derivation.js'

const seed = Uint8Array.from(
  ('000102030405060708090a0b0c0d0e0f'.match(/.{2}/g) ?? []).map((b) => Number.parseInt(b, 16)),
)

describe('paths', () => {
  test('authority sits under the delegable branch', () => {
    expect(authorityPath(0, 0, 0)).toBe("m/44'/876'/0'/0'/0'/0'/0'")
    expect(authorityPath(3, 1, 7)).toBe("m/44'/876'/0'/3'/0'/1'/7'")
  })

  test('key agreement sits under the delegable branch at role 1', () => {
    expect(agreementPath(3, 1, 7)).toBe("m/44'/876'/0'/3'/1'/1'/7'")
  })

  test('recovery sits on the root-retained branch, outside the profile subtree', () => {
    expect(recoveryPath(3)).toBe("m/44'/876'/1'/3'")
  })

  test('the recovery path is not a descendant of the delegable profile subtree', () => {
    // Handing out m/44'/876'/0'/<profile>' must not hand out the recovery key. Hardened
    // derivation is one-way, so this is guaranteed by the paths being siblings.
    expect(recoveryPath(3).startsWith("m/44'/876'/0'/3'")).toBe(false)
  })

  test('rejects a negative or non-integer index', () => {
    expect(() => authorityPath(-1, 0, 0)).toThrow(/non-negative integer/)
    expect(() => authorityPath(0, 1.5, 0)).toThrow(/non-negative integer/)
  })
})

describe('deriveKeyMaterial()', () => {
  test('is deterministic for the same seed, path and algorithm', () => {
    const a = deriveKeyMaterial(seed, authorityPath(0, 0, 0), 'EdDSA')
    const b = deriveKeyMaterial(seed, authorityPath(0, 0, 0), 'EdDSA')
    expect(a).toEqual(b)
  })

  test('separates algorithms at the same path', () => {
    const path = authorityPath(0, 0, 0)
    expect(deriveKeyMaterial(seed, path, 'EdDSA')).not.toEqual(
      deriveKeyMaterial(seed, path, 'ML-DSA-65'),
    )
  })

  test('produces the requested length, so 64-byte algorithms need no path tricks', () => {
    expect(deriveKeyMaterial(seed, authorityPath(0, 0, 0), 'ML-KEM-768', 64).length).toBe(64)
  })

  test('different positions produce different material', () => {
    expect(deriveKeyMaterial(seed, authorityPath(0, 0, 0), 'EdDSA')).not.toEqual(
      deriveKeyMaterial(seed, authorityPath(0, 0, 1), 'EdDSA'),
    )
  })
})

describe('deriveKeyPair()', () => {
  test('derives a 32-byte ed25519 keypair', () => {
    const { privateKey, publicKey } = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
    expect(privateKey.length).toBe(32)
    expect(publicKey.length).toBe(32)
  })

  test('rejects an algorithm it cannot build a keypair for', () => {
    expect(() => deriveKeyPair(seed, authorityPath(0, 0, 0), 'ML-DSA-65')).toThrow(/Unsupported/)
  })
})
