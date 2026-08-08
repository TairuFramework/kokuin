import { ed25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import HDKey from 'micro-key-producer/slip10.js'

import { VERSION_TAG } from './version.js'

const BASE_PATH = "m/44'/876'"
const DELEGABLE = "0'"
const ROOT_ONLY = "1'"
const ROLE_AUTHORITY = "0'"
const ROLE_AGREEMENT = "1'"

function assertIndex(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`Derivation: ${name} must be a non-negative integer, got ${value}`)
  }
}

function profilePath(profile: number): string {
  assertIndex('profile', profile)
  return `${BASE_PATH}/${DELEGABLE}/${profile}'`
}

/**
 * Authority signing key at a position. Lives under the delegable branch, so handing out the
 * profile sub-seed delegates it.
 */
export function authorityPath(profile: number, gen: number, seq: number): string {
  assertIndex('gen', gen)
  assertIndex('seq', seq)
  return `${profilePath(profile)}/${ROLE_AUTHORITY}/${gen}'/${seq}'`
}

/** Profile-level key agreement key. Durable data encrypts to these, never to device keys. */
export function agreementPath(profile: number, gen: number, seq: number): string {
  assertIndex('gen', gen)
  assertIndex('seq', seq)
  return `${profilePath(profile)}/${ROLE_AGREEMENT}/${gen}'/${seq}'`
}

/**
 * Recovery key, on the root-retained branch — a sibling of the delegable subtree, never a
 * descendant. Hardened derivation is one-way, so a sub-seed holder cannot reach it and the root
 * always keeps the one key that can supersede.
 */
export function recoveryPath(profile: number): string {
  assertIndex('profile', profile)
  return `${BASE_PATH}/${ROOT_ONLY}/${profile}'`
}

const KEY_LENGTHS: Record<string, number> = {
  EdDSA: 32,
  'ML-DSA-65': 32,
  'ML-KEM-768': 64,
}

/**
 * Key material for an algorithm at a path. SLIP-0010 fixes the tree position; HKDF supplies
 * algorithm separation and arbitrary lengths, so adding an algorithm needs a new `info` string
 * and no path change.
 */
export function deriveKeyMaterial(
  seed: Uint8Array,
  path: string,
  alg: string,
  length: number = KEY_LENGTHS[alg] ?? 32,
): Uint8Array {
  const node = HDKey.fromMasterSeed(seed).derive(path)
  const ikm = node.privateKey
  if (ikm == null) {
    throw new Error(`Derivation: no private key at path ${path}`)
  }
  const info = new TextEncoder().encode(`${VERSION_TAG}|${alg}`)
  return hkdf(sha256, ikm, undefined, info, length)
}

export function deriveKeyPair(
  seed: Uint8Array,
  path: string,
  alg: string,
): { privateKey: Uint8Array; publicKey: Uint8Array } {
  if (alg !== 'EdDSA') {
    throw new Error(`Derivation: Unsupported algorithm for key pair derivation: ${alg}`)
  }
  const privateKey = deriveKeyMaterial(seed, path, alg)
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) }
}
