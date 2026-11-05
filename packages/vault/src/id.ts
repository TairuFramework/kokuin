import { nobleCrypto } from '@kokuin/crypto'
import type { CryptoOptions } from '@kokuin/token'
import { concatBytes } from '@noble/hashes/utils.js'
import { fromUTF, toB64U } from '@sozai/codec'

// Unsigned varints: namespace 0xb6, key type 31, BLAKE3 digest length 32.
const KEY_ID_PREFIX = new Uint8Array([0xb6, 0x01, 31, 32])

/** Owner binding uses the exact owner bytes; callers normalise equality DIDs before minting. */
export type CreateVaultKeyIDParams = {
  owner: string | Uint8Array
  unique: Uint8Array
} & CryptoOptions

export async function createVaultKeyID({
  unique,
  owner,
  ...options
}: CreateVaultKeyIDParams): Promise<string> {
  const ownerBytes = typeof owner === 'string' ? fromUTF(owner) : owner
  const digest = await (options.crypto ?? nobleCrypto).blake3({
    input: concatBytes(ownerBytes, unique),
    dkLen: 32,
  })
  const bytes = concatBytes(KEY_ID_PREFIX, digest)
  let value = 0n

  for (const byte of bytes) value = (value << 8n) | BigInt(byte)

  return `k${value.toString(36)}`
}

/** Pair the owner commitment with the canonical unique bytes used by signed key metadata. */
export type CreateVaultKeyReferenceParams = { owner: string; unique: Uint8Array } & CryptoOptions

export async function createVaultKeyReference({
  unique,
  owner,
  ...options
}: CreateVaultKeyReferenceParams): Promise<{ keyID: string; keyUnique: string }> {
  const keyUnique = toB64U(unique)
  return { keyID: await createVaultKeyID({ ...options, owner, unique }), keyUnique }
}
