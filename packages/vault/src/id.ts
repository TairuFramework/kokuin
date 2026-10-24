import { blake3 } from '@noble/hashes/blake3.js'
import { concatBytes } from '@noble/hashes/utils.js'
import { fromUTF, toB64U } from '@sozai/codec'

// Unsigned varints: namespace 0xb6, key type 31, BLAKE3 digest length 32.
const KEY_ID_PREFIX = new Uint8Array([0xb6, 0x01, 31, 32])

/** Owner binding uses the exact owner bytes; callers normalise equality DIDs before minting. */
export function createVaultKeyID(owner: string | Uint8Array, unique: Uint8Array): string {
  const ownerBytes = typeof owner === 'string' ? fromUTF(owner) : owner
  const digest = blake3(concatBytes(ownerBytes, unique))
  const bytes = concatBytes(KEY_ID_PREFIX, digest)
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return `k${value.toString(36)}`
}

/** Pair the owner commitment with the canonical unique bytes used by signed key metadata. */
export function createVaultKeyReference(
  owner: string,
  unique: Uint8Array,
): { keyID: string; keyUnique: string } {
  return { keyID: createVaultKeyID(owner, unique), keyUnique: toB64U(unique) }
}
