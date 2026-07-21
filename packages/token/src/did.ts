import { base58 } from '@scure/base'

import type { DIDResolver } from './cache.js'
import { decodeMultibase } from './multibase.js'
import type { DIDDoc, VerificationMethod } from './peer4.js'
import {
  assertDocWithinMaxSize,
  decodePeer4,
  encodePeer4,
  getPeer4ShortForm,
  isPeer4,
} from './peer4.js'
import type { SignatureAlgorithm } from './schemas.js'

/** @internal */
export const CODECS: Record<SignatureAlgorithm, Uint8Array> = {
  ES256: new Uint8Array([128, 36]),
  EdDSA: new Uint8Array([0xed, 0x01]),
}

const EXPECTED_KEY_SIZES: Record<string, number> = {
  EdDSA: 32,
  ES256: 33,
}

const PREFIX = 'did:key:z'

// ES256 is the largest supported did:key payload: a 2-byte codec plus a 33-byte key
// encodes to 48 base58 characters. Bound before decoding — base58.decode is O(n^2).
const MAX_DID_KEY_ENCODED = 64

function isCodecMatch(codec: Uint8Array, bytes: Uint8Array): boolean {
  if (bytes.length < codec.length) return false
  for (let i = 0; i < codec.length; i++) {
    if (bytes[i] !== codec[i]) {
      return false
    }
  }
  return true
}

/** @internal */
export function getAlgorithmAndPublicKey(
  bytes: Uint8Array,
): [SignatureAlgorithm, Uint8Array] | null {
  for (const [alg, codec] of Object.entries(CODECS)) {
    if (isCodecMatch(codec, bytes)) {
      return [alg as SignatureAlgorithm, bytes.slice(codec.length)]
    }
  }
  return null
}

/** @internal */
export function getDID(codec: Uint8Array, publicKey: Uint8Array): string {
  const bytes = new Uint8Array(codec.length + publicKey.length)
  codec.forEach((v, i) => {
    bytes[i] = v
  })
  bytes.set(publicKey, codec.length)
  return PREFIX + base58.encode(bytes)
}

/** @internal */
export function getSignatureInfo(did: string): [SignatureAlgorithm, Uint8Array] {
  if (!did.startsWith(PREFIX)) {
    throw new Error('Invalid DID format')
  }

  const encoded = did.slice(PREFIX.length)
  if (encoded.length > MAX_DID_KEY_ENCODED) {
    throw new Error('Invalid DID format: key too large')
  }

  const bytes = base58.decode(encoded)
  const info = getAlgorithmAndPublicKey(bytes)
  if (info == null) {
    throw new Error('Unsupported DID signature codec')
  }

  const [alg, publicKey] = info
  const expectedSize = EXPECTED_KEY_SIZES[alg]
  if (expectedSize != null && publicKey.length !== expectedSize) {
    throw new Error('Invalid public key size')
  }
  return info
}

export type ResolveIssuerHeader = { kid?: string }

export type ResolveIssuerWithDocResult = {
  alg: SignatureAlgorithm
  publicKey: Uint8Array
  /** Present when iss was a peer:4 long form or resolver returned a doc — caller may use to populate a cache. */
  peer4Doc?: { shortForm: string; doc: DIDDoc }
}

/**
 * Resolve a token issuer (did:key or did:peer:4) and return alg + public key,
 * plus the decoded peer:4 doc when one was obtained inline or via the resolver.
 * Callers writing to a DID cache should write `peer4Doc` only after signature verification.
 */
export async function resolveIssuerWithDoc(
  iss: string,
  header: ResolveIssuerHeader = {},
  resolver?: DIDResolver,
): Promise<ResolveIssuerWithDocResult> {
  if (isPeer4(iss)) {
    const shortForm = getPeer4ShortForm(iss)

    if (iss !== shortForm) {
      const { doc } = decodePeer4(iss)
      const [alg, publicKey] = resolveKidOrAuth(doc, header.kid)
      return { alg, publicKey, peer4Doc: { shortForm, doc } }
    }

    if (resolver == null) {
      throw new Error(`Unknown DID: ${shortForm}`)
    }
    const doc = await resolver(shortForm)
    if (doc == null) {
      throw new Error(`Unknown DID: ${shortForm}`)
    }
    assertDocWithinMaxSize(doc)
    const expected = encodePeer4(doc).shortForm
    if (expected !== shortForm) {
      throw new Error('DIDResolver: short form/doc hash mismatch')
    }
    const [alg, publicKey] = resolveKidOrAuth(doc, header.kid)
    return { alg, publicKey, peer4Doc: { shortForm, doc } }
  }

  const [alg, publicKey] = getSignatureInfo(iss)
  return { alg, publicKey }
}

/**
 * Resolve a token issuer to [alg, publicKey]. Backward-compatible wrapper around resolveIssuerWithDoc.
 */
export async function resolveIssuer(
  iss: string,
  header: ResolveIssuerHeader = {},
  resolver?: DIDResolver,
): Promise<[SignatureAlgorithm, Uint8Array]> {
  const { alg, publicKey } = await resolveIssuerWithDoc(iss, header, resolver)
  return [alg, publicKey]
}

function resolveKidOrAuth(doc: DIDDoc, kid: string | undefined): [SignatureAlgorithm, Uint8Array] {
  if (kid == null) {
    const auth = doc.authentication
    if (auth == null || auth.length === 0) {
      throw new Error(
        'resolveIssuer: did:peer:4 token missing kid and doc has no authentication entries',
      )
    }
    return resolveKidFromDoc(doc, auth[0])
  }
  // A kid must reference a method the subject authorized for `authentication`. Without this
  // check a key listed only under `assertionMethod` (or any other relationship) could sign
  // tokens. `KidNotFound` still takes precedence so a genuinely absent kid is reported as such.
  const method = (doc.verificationMethod as Array<VerificationMethod>).find((m) => m.id === kid)
  if (method == null) {
    throw new Error(`KidNotFound: ${kid}`)
  }
  const auth = doc.authentication
  if (auth == null || !auth.includes(kid)) {
    throw new Error(`resolveIssuer: kid ${kid} is not an authentication method`)
  }
  return resolveKidFromDoc(doc, kid)
}

function resolveKidFromDoc(doc: DIDDoc, kid: string): [SignatureAlgorithm, Uint8Array] {
  const method = (doc.verificationMethod as Array<VerificationMethod>).find((m) => m.id === kid)
  if (method == null) {
    throw new Error(`KidNotFound: ${kid}`)
  }
  if (method.publicKeyMultibase.length > MAX_DID_KEY_ENCODED) {
    throw new Error('Invalid verification method: key too large')
  }
  const bytes = decodeMultibase(method.publicKeyMultibase)
  const info = getAlgorithmAndPublicKey(bytes)
  if (info == null) {
    throw new Error('Unsupported verification method codec')
  }
  return info
}

/**
 * Fold a DID to its canonical form for equality comparison.
 * For did:peer:4, returns the short form regardless of whether input is long or short.
 * All other DID methods pass through unchanged.
 */
export function normalizeDID(did: string): string {
  return isPeer4(did) ? getPeer4ShortForm(did) : did
}

/** Multicodec prefix for an X25519 public key, as published in a peer:4 doc. */
const CODEC_X25519_PUB = new Uint8Array([0xec, 0x01])

/**
 * The X25519 public key a DID document publishes for key agreement, or `null` when it
 * publishes none.
 *
 * Unlike a `did:key` EdDSA identity — whose agreement key is *derived* from its signing key
 * via the birational map — a peer:4 identity carries an independent agreement key in its doc.
 * A sender MUST use the published key: the derived one is a different key and will not decrypt.
 */
export function getAgreementKey(doc: DIDDoc): Uint8Array | null {
  const fragments = doc.keyAgreement
  if (fragments == null) {
    return null
  }
  for (const fragment of fragments) {
    const method = doc.verificationMethod.find(
      (verificationMethod: VerificationMethod) => verificationMethod.id === fragment,
    )
    if (method == null) {
      continue
    }
    // Bound before decoding — base58.decode is O(n^2) — same as resolveKidFromDoc().
    if (method.publicKeyMultibase.length > MAX_DID_KEY_ENCODED) {
      continue
    }
    let bytes: Uint8Array
    try {
      bytes = decodeMultibase(method.publicKeyMultibase)
    } catch {
      // A legal-but-unsupported multibase prefix (e.g. base64) shouldn't abort the scan of an
      // otherwise-good keyAgreement list — skip it, consistent with a missing method above.
      continue
    }
    if (!isCodecMatch(CODEC_X25519_PUB, bytes)) {
      continue
    }
    const publicKey = bytes.slice(CODEC_X25519_PUB.length)
    if (publicKey.length !== 32) {
      // Wrong-length key: treat like any other unusable entry so the caller gets the clear
      // "no agreement key" error instead of a RangeError from noble later.
      continue
    }
    return publicKey
  }
  return null
}
