import {
  CODECS,
  decryptToken,
  type FullIdentity,
  getDID,
  type SignedHeader,
  type SignedToken,
  type SigningIdentity,
  type SignTokenOptions,
} from '@kokuin/token'
import { x25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { b64uFromJSON, fromUTF, toB64U } from '@sozai/codec'

import { type BrowserKeyRecord, getES256PublicKey, type LegacyES256Record } from './utils.js'

/**
 * The current identity: non-extractable Ed25519 signing key, plus the X25519 agreement key
 * derived from it. `did:key` EdDSA, so it is addressable by every other kokuin backend and
 * decryptable by anyone who knows only its DID.
 */
export async function createBrowserIdentity(record: BrowserKeyRecord): Promise<FullIdentity> {
  const publicKey = record.publicKey
  const id = getDID(CODECS.EdDSA, publicKey)

  // The agreement key is stored as raw bytes (WebKit cannot persist an X25519 CryptoKey; see
  // BrowserKeyRecord). Re-import it here, non-extractable, for ECDH.
  const agreementPublic = x25519.getPublicKey(record.agreementSecret)
  const agreement = await globalThis.crypto.subtle.importKey(
    'jwk',
    {
      kty: 'OKP',
      crv: 'X25519',
      d: toB64U(record.agreementSecret),
      x: toB64U(agreementPublic),
    },
    { name: 'X25519' },
    false,
    ['deriveBits'],
  )

  async function signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options: SignTokenOptions = {},
  ): Promise<SignedToken<Payload>> {
    if (payload.iss != null && payload.iss !== id) {
      throw new Error('Invalid payload: issuer does not match signer')
    }

    const fullHeader = {
      ...(options.header ?? {}),
      typ: 'JWT',
      alg: 'EdDSA',
    } as SignedHeader
    const fullPayload = { ...payload, iss: id }
    const data = `${b64uFromJSON(fullHeader)}.${b64uFromJSON(fullPayload)}`

    // Ed25519 signatures are canonical — no low-S normalization needed, unlike ECDSA.
    const signature = await globalThis.crypto.subtle.sign(
      { name: 'Ed25519' },
      record.signing,
      fromUTF(data) as BufferSource,
    )

    return {
      header: fullHeader,
      payload: fullPayload,
      signature: toB64U(new Uint8Array(signature)),
      data,
    }
  }

  async function agreeKey(ephemeralPublicKey: Uint8Array): Promise<Uint8Array> {
    const ephemeral = await globalThis.crypto.subtle.importKey(
      'raw',
      ephemeralPublicKey as BufferSource,
      { name: 'X25519' },
      true,
      [],
    )
    const shared = await globalThis.crypto.subtle.deriveBits(
      { name: 'X25519', public: ephemeral },
      agreement,
      256,
    )
    return new Uint8Array(shared)
  }

  async function decrypt(jwe: string): Promise<Uint8Array> {
    return decryptToken({ id, decrypt, agreeKey }, jwe)
  }

  return { id, publicKey, signToken, decrypt, agreeKey }
}

// --- Legacy ES256 path ---
//
// Records minted before the Ed25519 migration. They can only sign: WebCrypto will not let an
// ECDSA key do deriveBits, so they cannot do ECDH, so they cannot decrypt. They keep working,
// and they are NEVER silently re-keyed — that would change the identity's DID under it.

const P256_N = p256.Point.Fn.ORDER

// Web Crypto's subtle.sign does not enforce low-S, so ~half of ECDSA signatures have s > n/2.
// The @kokuin/token verifier runs with `lowS: true` and rejects those for malleability safety.
function normalizeSignatureToLowS(sig: Uint8Array): Uint8Array {
  const parsed = p256.Signature.fromBytes(sig, 'compact')
  if (!parsed.hasHighS()) return sig
  return new p256.Signature(parsed.r, P256_N - parsed.s).toBytes('compact')
}

export async function createLegacyES256Identity(
  record: LegacyES256Record,
): Promise<SigningIdentity> {
  const publicKey = await getES256PublicKey(record)
  const id = getDID(CODECS.ES256, publicKey)

  async function signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options: SignTokenOptions = {},
  ): Promise<SignedToken<Payload>> {
    if (payload.iss != null && payload.iss !== id) {
      throw new Error('Invalid payload: issuer does not match signer')
    }

    const fullHeader = {
      ...(options.header ?? {}),
      typ: 'JWT',
      alg: 'ES256',
    } as SignedHeader
    const fullPayload = { ...payload, iss: id }
    const data = `${b64uFromJSON(fullHeader)}.${b64uFromJSON(fullPayload)}`

    const signature = await globalThis.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      record.privateKey,
      fromUTF(data) as BufferSource,
    )

    return {
      header: fullHeader,
      payload: fullPayload,
      signature: toB64U(normalizeSignatureToLowS(new Uint8Array(signature))),
      data,
    }
  }

  return { id, publicKey, signToken }
}
