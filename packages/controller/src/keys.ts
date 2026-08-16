import { decodeMultibase, encodeMultibase } from '@kokuin/token'

export type KeyAlgorithm = 'EdDSA' | 'X25519'

export type TaggedKey = { alg: KeyAlgorithm; publicKey: Uint8Array }

/**
 * Multicodec prefixes, following the `did:key` convention. Tagging is what makes a new algorithm
 * additive: an untagged key is opaque bytes, and telling X25519 from a future algorithm of the
 * same length would mean sniffing the length.
 */
const CODECS: Record<KeyAlgorithm, Uint8Array> = {
  EdDSA: new Uint8Array([0xed, 0x01]),
  X25519: new Uint8Array([0xec, 0x01]),
}

/**
 * Expected payload length per algorithm, checked after the codec prefix is stripped. A per-algorithm
 * table rather than a bare `=== 32`, so a future algorithm with a different length slots in without
 * touching this check. Without this, a bare untagged key can collide with a codec prefix by chance
 * (about 1 in 65536) and be silently accepted at the wrong length, and a truncated payload of the
 * right prefix but wrong length would mint a key that throws downstream instead of failing here.
 */
const KEY_LENGTHS: Record<KeyAlgorithm, number> = {
  EdDSA: 32,
  X25519: 32,
}

export function encodeKey(publicKey: Uint8Array, alg: KeyAlgorithm): string {
  const codec = CODECS[alg]
  const bytes = new Uint8Array(codec.length + publicKey.length)
  bytes.set(codec, 0)
  bytes.set(publicKey, codec.length)
  return encodeMultibase(bytes)
}

/** Total: any malformed, unknown-codec, or wrong-length value yields undefined rather than throwing. */
export function tryDecodeKey(value: string): TaggedKey | undefined {
  let bytes: Uint8Array
  try {
    bytes = decodeMultibase(value)
  } catch {
    return undefined
  }
  for (const alg of Object.keys(CODECS) as Array<KeyAlgorithm>) {
    const codec = CODECS[alg]
    if (bytes.length > codec.length && bytes[0] === codec[0] && bytes[1] === codec[1]) {
      const publicKey = bytes.slice(codec.length)
      if (publicKey.length !== KEY_LENGTHS[alg]) {
        return undefined
      }
      return { alg, publicKey }
    }
  }
  return undefined
}

export function decodeKey(value: string): TaggedKey {
  const key = tryDecodeKey(value)
  if (key == null) {
    throw new Error(`Unrecognised key encoding: ${value}`)
  }
  return key
}
