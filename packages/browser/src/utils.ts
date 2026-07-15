import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { toB64U } from '@sozai/codec'

/**
 * A key record minted by this version: non-extractable Ed25519 signing key plus the X25519
 * agreement key derived from it, and the Ed25519 public key the DID is built from.
 *
 * `suite` is what distinguishes it from a legacy record. An **untagged** record is ES256 by
 * definition — that is all a pre-migration record can be.
 */
export type BrowserKeyRecord = {
  suite: 'Ed25519'
  signing: CryptoKey
  agreement: CryptoKey
  publicKey: Uint8Array
}

/** A pre-migration record: a bare, untagged P-256 `CryptoKeyPair`. Signing only. */
export type LegacyES256Record = CryptoKeyPair

export type StoredKeyRecord = BrowserKeyRecord | LegacyES256Record

export function isLegacyES256Record(record: StoredKeyRecord): record is LegacyES256Record {
  return (record as BrowserKeyRecord).suite !== 'Ed25519'
}

/**
 * Throw unless WebCrypto can do Ed25519.
 *
 * There is deliberately **no fallback**. Falling back to P-256 would mint a different DID for
 * the same keyID, which is identity loss dressed up as graceful degradation. Requires
 * Chrome 137+, Firefox 130+, or Safari 17+.
 */
export async function assertEd25519Available(): Promise<void> {
  try {
    await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
  } catch (cause) {
    throw new Error(
      'WebCrypto does not support Ed25519, which @kokuin/browser requires (Chrome 137+, ' +
        'Firefox 130+, Safari 17+). Refusing to fall back to another curve: it would mint a ' +
        'different DID for the same keyID.',
      { cause },
    )
  }
}

/**
 * Mint a new key record.
 *
 * The seed is generated **here**, not by `subtle.generateKey`, and both keys are then imported
 * as non-extractable. This is forced, not stylistic: `jwe.ts` derives a recipient's agreement
 * key from its Ed25519 signing key (`toMontgomery`), so the agreement key MUST be the
 * birational image of the signing key. A `generateKey`'d X25519 keypair is independent, and
 * therefore unreachable by any sender — nothing addressed to the DID could ever be decrypted.
 * Deriving the montgomery secret needs the Ed25519 private scalar, which a non-extractable
 * `generateKey` result never yields.
 *
 * The cost is that the seed exists in the JS heap for the duration of this function. It is
 * zeroed on the way out, and IndexedDB only ever holds the non-extractable `CryptoKey`s — so
 * XSS at any point after provisioning still cannot exfiltrate the key.
 */
export async function generateKeyRecord(): Promise<BrowserKeyRecord> {
  await assertEd25519Available()

  const seed = ed25519.utils.randomSecretKey()
  const publicKey = ed25519.getPublicKey(seed)
  const agreementSecret = ed25519.utils.toMontgomerySecret(seed)
  const agreementPublic = x25519.getPublicKey(agreementSecret)

  try {
    const signing = await globalThis.crypto.subtle.importKey(
      'jwk',
      { kty: 'OKP', crv: 'Ed25519', d: toB64U(seed), x: toB64U(publicKey) },
      { name: 'Ed25519' },
      false,
      ['sign'],
    )
    const agreement = await globalThis.crypto.subtle.importKey(
      'jwk',
      { kty: 'OKP', crv: 'X25519', d: toB64U(agreementSecret), x: toB64U(agreementPublic) },
      { name: 'X25519' },
      false,
      ['deriveBits'],
    )
    return { suite: 'Ed25519', signing, agreement, publicKey }
  } finally {
    seed.fill(0)
    agreementSecret.fill(0)
  }
}

function ecPointCompress(x: Uint8Array, y: Uint8Array): Uint8Array {
  const out = new Uint8Array(x.length + 1)
  out[0] = 2 + (y[y.length - 1] & 1)
  out.set(x, 1)
  return out
}

/** The compressed P-256 public key of a legacy record. Legacy path only. */
export async function getES256PublicKey(keyPair: CryptoKeyPair): Promise<Uint8Array> {
  const rawKey = await globalThis.crypto.subtle.exportKey('raw', keyPair.publicKey)
  return ecPointCompress(new Uint8Array(rawKey.slice(1, 33)), new Uint8Array(rawKey.slice(33, 65)))
}
