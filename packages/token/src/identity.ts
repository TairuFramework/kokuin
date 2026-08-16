import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { b64uFromJSON, fromUTF, toB64U } from '@sozai/codec'
import { withSpan } from '@sozai/otel'

import { CODECS, getDID, normalizeDID } from './did.js'
import { encodeMultibase } from './multibase.js'
import { type DIDDoc, encodePeer4, isPeer4 } from './peer4.js'
import type { SignedHeader } from './schemas.js'
import type { DIDString, SignedToken } from './types.js'
import { concatBytes } from './utils.js'

const tracer = createTracer('token')

export type Identity = { readonly id: DIDString }

export type SignTokenOptions = {
  /** Extra header fields merged into the signed JWS header. */
  header?: Record<string, unknown>
  /** Pick a non-primary signing key by fragment (e.g. "#key-1"). */
  kid?: string
  /**
   * Override the long-form policy for did:peer:4 identities.
   * - true: always use long form (no-op for did:key, where longForm === id).
   * - false: always use short form.
   * - undefined (default): long form on the first token to a given `payload.aud`, short form
   *   thereafter; and always long form when the payload names no single string audience, since
   *   there is then no audience to key first contact on and the recipient may hold no cached
   *   document for this DID.
   */
  embedLongForm?: boolean
}

export type SigningIdentity = Identity & {
  publicKey: Uint8Array
  signToken: <Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options?: SignTokenOptions,
  ) => Promise<SignedToken<Payload>>
}

export type KeyAgreementIdentity = Identity & {
  agreeKey(ephemeralPublicKey: Uint8Array): Promise<Uint8Array>
}

export type FullIdentity = SigningIdentity & KeyAgreementIdentity

export type OwnIdentity = FullIdentity & { privateKey: Uint8Array }

export type IdentityProvider<T extends SigningIdentity = SigningIdentity> = {
  provideIdentity(keyID: string): Promise<T>
}

export function isSigningIdentity(identity: Identity): identity is SigningIdentity {
  return (
    'publicKey' in identity &&
    'signToken' in identity &&
    typeof (identity as SigningIdentity).signToken === 'function'
  )
}

export function isKeyAgreementIdentity(identity: Identity): identity is KeyAgreementIdentity {
  return 'agreeKey' in identity && typeof (identity as KeyAgreementIdentity).agreeKey === 'function'
}

export function isFullIdentity(identity: Identity): identity is FullIdentity {
  return isSigningIdentity(identity) && isKeyAgreementIdentity(identity)
}

export function isOwnIdentity(identity: Identity): identity is OwnIdentity {
  return isFullIdentity(identity) && 'privateKey' in identity
}

/**
 * Create a signing identity for an Ed25519 private key under a caller-supplied DID.
 *
 * `createSigningIdentity` derives the DID *from* the key, which only works for `did:key`. A method
 * whose identifier is not a function of the current key — `did:kokuin:`, where the key rotates under
 * a fixed inception digest — must supply its own `id`, so `iss` is the method's DID, not the key's
 * `did:key`. The caller owns the pairing: nothing here checks `id` resolves to `privateKey`'s public
 * key, and a mismatch produces tokens that verify nowhere.
 */
export function createSigningIdentityForDID(
  id: DIDString,
  privateKey: Uint8Array,
): SigningIdentity {
  return buildSigningIdentity(id, privateKey, ed25519.getPublicKey(privateKey))
}

// Shared body. Takes `publicKey` rather than deriving it, so `createSigningIdentity` — which
// needs the public key anyway to build the `did:key` — derives it once instead of twice.
function buildSigningIdentity(
  id: DIDString,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): SigningIdentity {
  async function signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options: SignTokenOptions = {},
  ): Promise<SignedToken<Payload>> {
    return withSpan(
      tracer,
      KokuinSpanNames.TOKEN_SIGN,
      {
        attributes: {
          [KokuinAttributeKeys.AUTH_DID]: id,
          [KokuinAttributeKeys.AUTH_ALGORITHM]: 'EdDSA',
        },
      },
      async () => {
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

        return {
          header: fullHeader,
          payload: fullPayload,
          signature: toB64U(ed25519.sign(fromUTF(data), privateKey)),
          data,
        }
      },
    )
  }

  return { id, publicKey, signToken }
}

/**
 * Create a signing identity from an Ed25519 private key.
 */
export function createSigningIdentity(privateKey: Uint8Array): SigningIdentity {
  const publicKey = ed25519.getPublicKey(privateKey)
  return buildSigningIdentity(getDID(CODECS.EdDSA, publicKey), privateKey, publicKey)
}

/**
 * Create a key-agreement identity from an Ed25519 private key.
 * Uses X25519 key derivation for ECDH key agreement.
 */
export function createKeyAgreementIdentity(privateKey: Uint8Array): KeyAgreementIdentity {
  const publicKey = ed25519.getPublicKey(privateKey)
  const id = getDID(CODECS.EdDSA, publicKey)
  const x25519Private = ed25519.utils.toMontgomerySecret(privateKey)

  async function agreeKey(ephemeralPublicKey: Uint8Array): Promise<Uint8Array> {
    return x25519.getSharedSecret(x25519Private, ephemeralPublicKey)
  }

  return { id, agreeKey }
}

/**
 * Create a full identity (signing + key agreement) from an Ed25519 private key.
 */
export function createFullIdentity(privateKey: Uint8Array): FullIdentity {
  const signing = createSigningIdentity(privateKey)
  const keyAgreement = createKeyAgreementIdentity(privateKey)
  return { ...signing, ...keyAgreement }
}

/**
 * Generate a random identity with a new Ed25519 private key.
 */
export function randomIdentity(): OwnIdentity {
  const privateKey = ed25519.utils.randomSecretKey()
  return { ...createFullIdentity(privateKey), privateKey }
}

// ─── createIdentity builder ────────────────────────────────────────────────

export type KeyPurpose = 'sig' | 'kem'
export type KeyAlg = 'EdDSA' | 'X25519'

export type IdentityKeySpec = {
  purpose: KeyPurpose
  alg: KeyAlg
  /**
   * Optional caller-supplied private key bytes.
   *
   * - When provided, the key pair is derived deterministically from these bytes.
   *   For a single-key spec on `did:peer:4`, this means the resulting short form
   *   is also deterministic — useful for reproducible identities (tests, seed-based
   *   recovery, restoring an identity from a stored secret).
   * - When omitted, a fresh random key is generated via the algorithm's
   *   `randomSecretKey()` utility (Ed25519 or X25519).
   *
   * The caller owns the lifecycle of the supplied bytes.
   */
  privateKey?: Uint8Array
}

export type CreateIdentityInput = {
  keys: Array<IdentityKeySpec>
  didMethod?: 'key' | 'peer:4'
}

export type ResolvedKey = {
  fragment: string
  alg: KeyAlg
  purpose: KeyPurpose
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export type MultiKeyIdentity = {
  id: DIDString
  longForm: DIDString
  doc: DIDDoc
  keys: Array<ResolvedKey>
  publicKey: Uint8Array
  privateKey: Uint8Array
  signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options?: SignTokenOptions,
  ): Promise<SignedToken<Payload>>
  agreeKey(ephemeralPublicKey: Uint8Array, kid?: string): Promise<Uint8Array>
}

const CODEC_ED25519_PUB = new Uint8Array([0xed, 0x01])
const CODEC_X25519_PUB = new Uint8Array([0xec, 0x01])

function codecFor(alg: KeyAlg): Uint8Array {
  switch (alg) {
    case 'EdDSA':
      return CODEC_ED25519_PUB
    case 'X25519':
      return CODEC_X25519_PUB
  }
}

function publicKeyMultibase(alg: KeyAlg, publicKey: Uint8Array): string {
  return encodeMultibase(concatBytes(codecFor(alg), publicKey))
}

function generateKeyPair(
  alg: KeyAlg,
  providedPrivate?: Uint8Array,
): { privateKey: Uint8Array; publicKey: Uint8Array } {
  switch (alg) {
    case 'EdDSA': {
      const priv = providedPrivate ?? ed25519.utils.randomSecretKey()
      return { privateKey: priv, publicKey: ed25519.getPublicKey(priv) }
    }
    case 'X25519': {
      const priv = providedPrivate ?? x25519.utils.randomSecretKey()
      return { privateKey: priv, publicKey: x25519.getPublicKey(priv) }
    }
  }
}

function isClassical(spec: IdentityKeySpec): boolean {
  return spec.alg === 'EdDSA' || spec.alg === 'X25519'
}

function chooseMethod(input: CreateIdentityInput): 'key' | 'peer:4' {
  if (input.didMethod != null) {
    if (input.didMethod === 'key') {
      if (input.keys.length !== 1) {
        throw new Error('IdentityError.InvalidMethod: did:key requires exactly one key')
      }
      if (!isClassical(input.keys[0])) {
        throw new Error('IdentityError.InvalidMethod: did:key requires a classical algorithm')
      }
      if (input.keys[0].purpose !== 'sig') {
        throw new Error('IdentityError.InvalidMethod: did:key requires a signing key')
      }
    }
    return input.didMethod
  }
  if (input.keys.length === 1 && isClassical(input.keys[0]) && input.keys[0].purpose === 'sig') {
    return 'key'
  }
  return 'peer:4'
}

function resolveKeys(input: CreateIdentityInput): Array<ResolvedKey> {
  return input.keys.map((spec, i) => {
    const { privateKey, publicKey } = generateKeyPair(spec.alg, spec.privateKey)
    return {
      fragment: `#key-${i}`,
      alg: spec.alg,
      purpose: spec.purpose,
      privateKey,
      publicKey,
    }
  })
}

function buildDoc(keys: Array<ResolvedKey>): DIDDoc {
  const verificationMethod = keys.map((k) => ({
    id: k.fragment,
    type: 'Multikey',
    publicKeyMultibase: publicKeyMultibase(k.alg, k.publicKey),
  }))
  const authentication = keys.filter((k) => k.purpose === 'sig').map((k) => k.fragment)
  const keyAgreement = keys.filter((k) => k.purpose === 'kem').map((k) => k.fragment)
  const doc: DIDDoc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod,
  }
  if (authentication.length > 0) doc.authentication = authentication
  if (keyAgreement.length > 0) doc.keyAgreement = keyAgreement
  return doc
}

function pickSigningKey(keys: Array<ResolvedKey>, kid?: string): ResolvedKey {
  if (kid != null) {
    const found = keys.find((k) => k.fragment === kid)
    if (found == null) throw new Error(`KidNotFound: ${kid}`)
    if (found.purpose !== 'sig') throw new Error(`Kid is not a signing key: ${kid}`)
    return found
  }
  const first = keys.find((k) => k.purpose === 'sig')
  if (first == null) throw new Error('No signing key in identity')
  return first
}

function signWith(key: ResolvedKey, data: Uint8Array): Uint8Array {
  switch (key.alg) {
    case 'EdDSA':
      return ed25519.sign(data, key.privateKey)
    case 'X25519':
      throw new Error('X25519 cannot sign')
  }
}

/**
 * The X25519 private scalar this identity agrees with, for `kid` or by default.
 *
 * A peer:4 identity uses its published `keyAgreement` key. A `did:key` EdDSA identity has no
 * published agreement key — a sender derives one from its signing key via the birational map —
 * so it must derive the matching secret the same way, exactly as `createKeyAgreementIdentity` does.
 */
function pickAgreementSecret(keys: Array<ResolvedKey>, isPeer: boolean, kid?: string): Uint8Array {
  if (kid != null) {
    // No birational fallback here, unlike the no-kid branch below: a kid names one specific
    // key, so falling back to a *different*, derived key would silently agree with the wrong
    // secret. This means a did:key identity's agreeKey(epk, '#key-0') throws where
    // agreeKey(epk) succeeds — a known asymmetry, currently unreachable: decryptToken
    // (@kokuin/jwe) never passes a kid, and KeyAgreementIdentity#agreeKey has no kid parameter
    // at all.
    const found = keys.find((key) => key.fragment === kid)
    if (found == null) throw new Error(`KidNotFound: ${kid}`)
    if (found.purpose !== 'kem' || found.alg !== 'X25519') {
      throw new Error(`Kid is not a KEM X25519 key: ${kid}`)
    }
    return found.privateKey
  }
  const kem = keys.find((key) => key.purpose === 'kem' && key.alg === 'X25519')
  if (kem != null) {
    return kem.privateKey
  }
  if (!isPeer) {
    const sig = keys.find((key) => key.purpose === 'sig' && key.alg === 'EdDSA')
    if (sig != null) {
      return ed25519.utils.toMontgomerySecret(sig.privateKey)
    }
  }
  throw new Error('No KEM key in identity')
}

function buildIdentity(
  id: DIDString,
  longForm: DIDString,
  doc: DIDDoc,
  keys: Array<ResolvedKey>,
): MultiKeyIdentity {
  const primarySig = keys.find((k) => k.purpose === 'sig')
  if (primarySig == null) {
    throw new Error('createIdentity requires at least one signing key')
  }
  const sentTo = new Set<string>()
  const isPeer = isPeer4(id)

  function pickIss(
    payload: Record<string, unknown>,
    embedLongForm: boolean | undefined,
  ): DIDString {
    if (!isPeer) return id
    if (embedLongForm === true) return longForm
    if (embedLongForm === false) return id
    const aud = payload.aud
    // No single named audience: there is nothing to key first-contact on, and the recipient may
    // never have seen this doc. Embed the long form so the token resolves standalone.
    if (typeof aud !== 'string') return longForm
    const normalizedAud = normalizeDID(aud)
    if (sentTo.has(normalizedAud)) return id
    // Concurrent sign() calls with the same new aud may both emit long-form; recipient cache writes are idempotent so this is acceptable.
    sentTo.add(normalizedAud)
    return longForm
  }

  async function signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options: SignTokenOptions = {},
  ): Promise<SignedToken<Payload>> {
    const key = pickSigningKey(keys, options.kid)
    const iss = pickIss(payload as Record<string, unknown>, options.embedLongForm)
    const header = {
      ...(options.header ?? {}),
      typ: 'JWT',
      alg: 'EdDSA',
      ...(isPeer ? { kid: key.fragment } : {}),
    } as SignedHeader
    const fullPayload = { ...payload, iss }
    const data = `${b64uFromJSON(header)}.${b64uFromJSON(fullPayload)}`
    return {
      header: header as SignedHeader & Record<string, unknown>,
      payload: fullPayload as Payload & { iss: string },
      signature: toB64U(signWith(key, fromUTF(data))),
      data,
    } as SignedToken<Payload>
  }

  async function agreeKey(ephemeralPublicKey: Uint8Array, kid?: string): Promise<Uint8Array> {
    return x25519.getSharedSecret(pickAgreementSecret(keys, isPeer, kid), ephemeralPublicKey)
  }

  return {
    id,
    longForm,
    doc,
    keys,
    publicKey: primarySig.publicKey,
    privateKey: primarySig.privateKey,
    signToken,
    agreeKey,
  }
}

/**
 * Build a multi-key identity from one or more key specs.
 *
 * DID method selection:
 * - Single classical (`EdDSA` / `X25519`) signing key with no override → `did:key`.
 * - Anything else (multiple keys, KEM-only, any non-classical algorithm) → `did:peer:4`.
 * - Caller may force a method via `input.didMethod`. Invalid combinations throw
 *   `IdentityError.InvalidMethod` (e.g. forcing `did:key` with multiple keys).
 *
 * Key resolution:
 * - Each `IdentityKeySpec.privateKey` is honored when present (deterministic), otherwise
 *   a fresh random key is generated. See {@link IdentityKeySpec.privateKey}.
 * - At least one signing key (`purpose: 'sig'`) is required; the first becomes the
 *   identity's primary signing key and seeds `publicKey` / `privateKey` on the result.
 *
 * For `did:peer:4`, the returned `id` is the short form (hash of the doc) and is
 * deterministic with respect to the resolved keys — providing the same `privateKey`
 * bytes across runs yields the same short form. `longForm` carries the full doc and
 * is what peers exchange for first contact (see `signToken({ embedLongForm })`).
 *
 * @throws `Error` when `input.keys` is empty or no `sig` key is provided.
 * @throws `IdentityError.InvalidMethod` when `didMethod` cannot satisfy the key set.
 */
export async function createIdentity(input: CreateIdentityInput): Promise<MultiKeyIdentity> {
  if (input.keys.length === 0) {
    throw new Error('createIdentity requires at least one key')
  }
  const method = chooseMethod(input)
  const keys = resolveKeys(input)

  if (method === 'key') {
    const [k] = keys
    const id = getDID(CODECS.EdDSA, k.publicKey)
    const doc: DIDDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        {
          id: '#key-0',
          type: 'Multikey',
          publicKeyMultibase: publicKeyMultibase(k.alg, k.publicKey),
        },
      ],
      authentication: ['#key-0'],
    }
    return buildIdentity(id, id, doc, keys)
  }

  const doc = buildDoc(keys)
  const { longForm, shortForm } = encodePeer4(doc)
  return buildIdentity(shortForm, longForm, doc, keys)
}
