import { base58 } from '@scure/base'

import type { DIDResolver } from './cache.js'
import { findMethodResolver, type MethodRegistry, type ResolvedSigningKey } from './method.js'
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
import type { DIDString } from './types.js'

/**
 * Multicodec prefixes per signature algorithm, following the `did:key` convention. Supported, not
 * internal: `@kokuin/capability` builds the `cnf.kid` confirmation claim from this and
 * {@link getAlgorithmAndPublicKey}, and `cnf.kid` is a published wire format third parties produce
 * and read.
 */
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

/**
 * Split multicodec-prefixed key bytes into their algorithm and the raw public key, or `null` when
 * the prefix names no algorithm this package knows.
 *
 * The decoder half of the `cnf.kid` wire format — see {@link CODECS}.
 */
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
export function getDID(codec: Uint8Array, publicKey: Uint8Array): DIDString {
  const bytes = new Uint8Array(codec.length + publicKey.length)
  codec.forEach((v, i) => {
    bytes[i] = v
  })
  bytes.set(publicKey, codec.length)
  return `${PREFIX}${base58.encode(bytes)}`
}

/**
 * The signature algorithm and raw public key a `did:key` identifier carries. Throws when the string
 * is not a `did:key`, its encoded form is implausibly long, or the codec names no supported
 * algorithm.
 *
 * Supported, not internal: `@kumiai/mls` checks an MLS credential's key against the key its DID
 * names, a comparison only this function makes correctly — the alternative is a second decoder in
 * another repo whose failure mode is accepting a credential for the wrong key. Any other method
 * resolves through a `DIDMethodResolver`; this is the self-contained case.
 */
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

const UNRESOLVABLE_ISSUER_BRAND = '@kokuin/token/UnresolvableIssuerError'

/**
 * The issuer could not be resolved to a usable signing key: no method, resolver, or registry entry
 * turned `iss` into one — including a resolver that has no answer, throws, or answers with something
 * unusable (an oversized document, or one not hashing to the DID asked for).
 *
 * Distinct from every other verification failure on purpose. An invalid signature or a bad `kid`
 * means the issuer *was* resolved and the token is bad (positive evidence); this means nothing was
 * learned either way, and a caller treating "could not check" as "checked and fine" fails open.
 * `@kokuin/capability`'s revocation checker turns on this distinction, so it must be a type, not a
 * message — text matching is how such a check regresses silently.
 */
export class UnresolvableIssuerError extends Error {
  /**
   * Identifies the error by value, not identity: within this package `instanceof` is exact, but a
   * duplicated `@kokuin/token` in a consumer's tree would make a cross-copy `instanceof` false (which
   * fails closed, so this is hardening). Consumers should use `isUnresolvableIssuerError`.
   */
  static get brand(): string {
    return UNRESOLVABLE_ISSUER_BRAND
  }

  /** The brand, readable from an instance — what `isUnresolvableIssuerError` matches on. */
  get brand(): string {
    return UNRESOLVABLE_ISSUER_BRAND
  }

  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'UnresolvableIssuerError'
  }
}

/**
 * Whether a thrown value means the issuer could not be resolved.
 *
 * Prefer this to `instanceof UnresolvableIssuerError` across a package boundary: it matches on the
 * brand, so it holds even if the thrower and the checker resolved different copies of this package.
 */
export function isUnresolvableIssuerError(value: unknown): value is UnresolvableIssuerError {
  return (
    value instanceof Error && (value as { brand?: unknown }).brand === UNRESOLVABLE_ISSUER_BRAND
  )
}

const ISSUER_KEY_NOT_FOUND_BRAND = '@kokuin/token/IssuerKeyNotFoundError'

/**
 * A DID method resolved the issuer, and the token then named a key that issuer does not have. The
 * counterpart of {@link UnresolvableIssuerError}: a `DIDMethodResolver` needs a way to say "resolved,
 * and the token is bad" too, else `resolveIssuerWithDoc` wraps everything a method throws as
 * unresolvable and an unauthenticated `kid` naming a real DID and an invented key reads as "could not
 * check" rather than "checked, and bad". Throw it only for that; not knowing the DID at all is
 * {@link UnresolvableIssuerError}.
 */
export class IssuerKeyNotFoundError extends Error {
  /** @see UnresolvableIssuerError.brand — same reasoning, across the same package boundary. */
  static get brand(): string {
    return ISSUER_KEY_NOT_FOUND_BRAND
  }

  /** The brand, readable from an instance — what `isIssuerKeyNotFoundError` matches on. */
  get brand(): string {
    return ISSUER_KEY_NOT_FOUND_BRAND
  }

  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'IssuerKeyNotFoundError'
  }
}

/**
 * Whether a thrown value means the issuer resolved but does not have the key the token named.
 *
 * Prefer this to `instanceof IssuerKeyNotFoundError` across a package boundary, for the same
 * reason as {@link isUnresolvableIssuerError}.
 */
export function isIssuerKeyNotFoundError(value: unknown): value is IssuerKeyNotFoundError {
  return (
    value instanceof Error && (value as { brand?: unknown }).brand === ISSUER_KEY_NOT_FOUND_BRAND
  )
}

export type ResolveIssuerHeader = { kid?: string }

export type ResolveIssuerWithDocResult = {
  alg: SignatureAlgorithm
  publicKey: Uint8Array
  /** Present when iss was a peer:4 long form or resolver returned a doc — caller may use to populate a cache. */
  peer4Doc?: { shortForm: string; doc: DIDDoc }
}

/**
 * Whether to resolve the issuer's *current* signing key or one it signed with in the past. `false`
 * (default) asks {@link DIDMethodResolver.resolve} — the safe question, right for a live signer.
 * `true` asks {@link DIDMethodResolver.resolveHistoric}, an explicit statement that the artefact was
 * issued in the past and must survive key rotation. A resolver with no `resolveHistoric` **refuses**
 * rather than falling back to `resolve`, which would be the permissive scan by another name.
 */
export type ResolveIssuerMode = { historic?: boolean }

/** Params for {@link resolveIssuer} / {@link resolveIssuerWithDoc}. */
export type ResolveIssuerParams = {
  iss: string
  header?: ResolveIssuerHeader
  resolver?: DIDResolver
  methods?: MethodRegistry
  /** See {@link ResolveIssuerMode.historic}. */
  historic?: boolean
}

/**
 * Resolve a token issuer (did:key or did:peer:4) and return alg + public key,
 * plus the decoded peer:4 doc when one was obtained inline or via the resolver.
 * Callers writing to a DID cache should write `peer4Doc` only after signature verification.
 *
 * The `historic` param selects which question is asked of a `DIDMethodResolver` — see
 * {@link ResolveIssuerMode}. It reaches only the method-registry branch: `did:key` carries its key
 * in the identifier and a `did:peer:4` document is fixed by its own hash, so neither has a past key
 * set distinct from its present one.
 */
export async function resolveIssuerWithDoc({
  iss,
  header = {},
  resolver,
  methods,
  historic = false,
}: ResolveIssuerParams): Promise<ResolveIssuerWithDocResult> {
  if (methods != null) {
    const methodResolver = findMethodResolver(methods, iss)
    if (methodResolver != null) {
      // The historic question is answered only by `resolveHistoric`; a resolver without one is not
      // asked `resolve` instead, which would substitute a different question. `UnresolvableIssuerError`
      // is right — nothing was learned either way, which a fail-closed caller treats as a denial.
      if (historic && methodResolver.resolveHistoric == null) {
        throw new UnresolvableIssuerError(
          `DID method ${methodResolver.method} cannot resolve historic keys: ${iss}`,
        )
      }
      // A method resolver throws its own error strings; re-type them so a method-backed resolution
      // failure is indistinguishable from the built-in ones below. Message preserved, original kept
      // as `cause`.
      let resolved: ResolvedSigningKey
      try {
        // Called as a method of its own resolver, not detached: an implementation may be a class with
        // private state.
        resolved =
          historic && methodResolver.resolveHistoric != null
            ? await methodResolver.resolveHistoric(iss, header)
            : await methodResolver.resolve(iss, header)
      } catch (cause) {
        // Except the one failure that is not a failure to resolve: "I have this issuer, it has no such
        // key" is what the `kid` branches below report for `did:peer:4` (ordinary errors — see
        // IssuerKeyNotFoundError). Wrapping it would let an unauthenticated header make any issuer read
        // as unresolvable, which callers fail closed on.
        if (isIssuerKeyNotFoundError(cause)) {
          throw cause
        }
        throw new UnresolvableIssuerError(
          cause instanceof Error ? cause.message : `Unknown DID: ${iss}`,
          { cause },
        )
      }
      return { alg: resolved.alg, publicKey: resolved.publicKey }
    }
  }

  if (isPeer4(iss)) {
    const shortForm = getPeer4ShortForm(iss)

    if (iss !== shortForm) {
      const { doc } = decodePeer4(iss)
      const [alg, publicKey] = resolveKidOrAuth(doc, header.kid)
      return { alg, publicKey, peer4Doc: { shortForm, doc } }
    }

    if (resolver == null) {
      throw new UnresolvableIssuerError(`Unknown DID: ${shortForm}`)
    }
    // Throwing is the normal style for a network-backed resolver, so one that throws must be
    // indistinguishable from one that returns nothing — else the fail-closed guarantee holds only for
    // resolvers that signal failure by returning `undefined`.
    let doc: DIDDoc | undefined
    try {
      doc = await resolver(shortForm)
    } catch (cause) {
      throw new UnresolvableIssuerError(`Unknown DID: ${shortForm}`, { cause })
    }
    if (doc == null) {
      throw new UnresolvableIssuerError(`Unknown DID: ${shortForm}`)
    }
    // An unusable answer — oversized, or not hashing to the DID asked for — counts as unresolvable,
    // not an ordinary fault: else a caller failing closed solely on `UnresolvableIssuerError` takes a
    // broken or lying resolver as "not revoked". No availability cost worth weighing — a resolver
    // willing to lie about documents already controls resolution completely.
    try {
      assertDocWithinMaxSize(doc)
    } catch (cause) {
      throw new UnresolvableIssuerError(
        cause instanceof Error ? cause.message : `Unknown DID: ${shortForm}`,
        { cause },
      )
    }
    const expected = encodePeer4(doc).shortForm
    if (expected !== shortForm) {
      throw new UnresolvableIssuerError('DIDResolver: short form/doc hash mismatch')
    }
    const [alg, publicKey] = resolveKidOrAuth(doc, header.kid)
    return { alg, publicKey, peer4Doc: { shortForm, doc } }
  }

  // `iss` narrows to `never` here (isPeer4's `value is string` collapses the false case), so route
  // the prefix check through a helper taking an unnarrowed `string`.
  if (!hasKeyPrefix(iss)) {
    throw new UnresolvableIssuerError(`Unknown DID: ${iss}`)
  }
  const [alg, publicKey] = getSignatureInfo(iss)
  return { alg, publicKey }
}

function hasKeyPrefix(did: string): boolean {
  return did.startsWith(PREFIX)
}

/**
 * Resolve a token issuer to [alg, publicKey]. Backward-compatible wrapper around resolveIssuerWithDoc.
 */
export async function resolveIssuer({
  iss,
  header = {},
  resolver,
  methods,
  historic = false,
}: ResolveIssuerParams): Promise<[SignatureAlgorithm, Uint8Array]> {
  const { alg, publicKey } = await resolveIssuerWithDoc({
    iss,
    header,
    resolver,
    methods,
    historic,
  })
  return [alg, publicKey]
}

function resolveKidOrAuth(doc: DIDDoc, kid: string | undefined): [SignatureAlgorithm, Uint8Array] {
  if (kid == null) {
    const firstAuth = doc.authentication?.[0]
    if (firstAuth == null) {
      throw new Error(
        'resolveIssuer: did:peer:4 token missing kid and doc has no authentication entries',
      )
    }
    return resolveKidFromDoc(doc, firstAuth)
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
