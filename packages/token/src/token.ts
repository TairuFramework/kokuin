import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import { b64uFromJSON, b64uToJSON, canonicalStringify, fromB64U, fromUTF } from '@sozai/codec'
import { withSpan } from '@sozai/otel'
import { assertType, isType } from '@sozai/schema'

import type { DIDCache, DIDResolver } from './cache.js'
import { resolveIssuerWithDoc } from './did.js'
import type { SigningIdentity } from './identity.js'
import type { MethodRegistry } from './method.js'
import {
  type SignedPayload,
  validateAlgorithm,
  validateSignedHeader,
  validateSignedPayload,
  validateUnsignedHeader,
} from './schemas.js'
import { assertTimeClaimsValid, type TimeValidationOptions } from './time.js'
import type { DIDString, SignedToken, Token, UnsignedToken, VerifiedToken } from './types.js'
import { getVerifier, type Verifiers } from './verifier.js'

const tokenTracer = createTracer('token')

// Tokens whose signature was verified in this process. Deserialized JSON can carry a
// `verifiedPublicKey` property but can never be a member of this set, so verification
// is only ever skipped for objects produced by `verifyToken` itself.
const verifiedTokens = new WeakSet<object>()

// The `data` string each verified token's signature was checked against, keyed off the object
// rather than read back from it. `token.data` is a mutable property of that same object, so
// comparing a recomputed header/payload against it is vacuous: code that mutates the payload can
// re-derive `data` from the mutation and stay self-consistent. This map is not reachable from the
// token, so the value captured at verification time is the one the re-bind compares against.
const verifiedTokenData = new WeakMap<object, string>()

// Tokens verified with `historic: true` — against a key the issuer has since rotated away.
// Membership blocks the fast path: a later `verifyToken` without `historic` asks the stricter
// question, and answering it from a weaker check is fail-open, so it re-verifies (which may pass).
// The reverse needs nothing — a strict answer already implies the loose one.
const historicallyVerifiedTokens = new WeakSet<object>()

export type VerifyTokenOptions = TimeValidationOptions & {
  verifiers?: Verifiers
  resolver?: DIDResolver
  cache?: DIDCache
  /**
   * DID methods that need external resolution to verify an issuer. `did:key` and `did:peer:4` need no
   * entry (they carry their key in the identifier or document); a method whose key set is a projection
   * of state held elsewhere — `did:kokuin:` — cannot be verified without one, and fails with `Unknown
   * DID` when no registry is passed.
   */
  methods?: MethodRegistry
  /**
   * Expected audience(s) for the token. When set, verification rejects a token whose `aud`
   * claim is not among the given value(s), and rejects unsigned / `alg:none` tokens outright
   * (they carry no proof of their claims). Intended for the invocation/leaf token directed at
   * a service — it must NOT be forwarded into capability-chain verification, where a
   * capability's `aud` is the delegation next-hop rather than a service audience. An empty
   * array accepts no audience (every token is rejected).
   */
  audience?: DIDString | Array<DIDString>
  /**
   * Verify against a key the issuer has already rotated away, as well as its current ones. Defaults
   * to `false` — the safe question: the signature must be from a key the issuer holds **now**, so a
   * rotated-away (leaked) key mints nothing. Opting in asks whether the issuer held the key **at some
   * point**, which a past-issued capability or revocation record needs to survive routine key hygiene.
   *
   * Set it only for a past-issued token that is not itself proof a live party holds a key. Not a
   * compatibility switch: it is the difference between "a compromised key mints nothing" and "mints
   * anything until the profile resets". A resolver with no `resolveHistoric` rejects with
   * `UnresolvableIssuerError` rather than answering the current-key question.
   */
  historic?: boolean
  /**
   * Accept unsigned (`alg:none`) tokens. Defaults to `false`.
   *
   * An unsigned token carries no proof of its claims: its payload is entirely
   * attacker-chosen. With the default, `verifyToken` rejects them and its return type is
   * `VerifiedToken`, so a caller cannot reach an unverified payload by accident. Only opt
   * in when the payload is not used for authorization.
   */
  allowUnsigned?: boolean
}

function assertAudienceValid(
  payload: Record<string, unknown>,
  audience?: DIDString | Array<DIDString>,
): void {
  if (audience == null) {
    return
  }
  const aud = payload.aud
  const allowed = Array.isArray(audience) ? audience : [audience]
  if (typeof aud !== 'string' || !allowed.includes(aud as DIDString)) {
    throw new Error(
      `Invalid token: audience ${typeof aud === 'string' ? `"${aud}"` : 'missing'} not accepted`,
    )
  }
}

// An unsigned / `alg:none` token carries no proof of its claims, so it cannot satisfy an
// audience requirement. Reject it rather than silently skipping the check.
function assertSignedForAudience(audience?: string | Array<string>): void {
  if (audience != null) {
    throw new Error('Invalid token: audience validation requires a signed token')
  }
}

function assertUnsignedAllowed(allowUnsigned: boolean): void {
  if (!allowUnsigned) {
    throw new Error('Invalid token: unsigned tokens rejected, pass allowUnsigned to accept')
  }
}

export type VerifySignedPayloadInput<
  Payload extends Record<string, unknown> = Record<string, unknown>,
> = {
  signature: Uint8Array
  payload: Payload
  header: { alg?: string; kid?: string }
  data: Uint8Array | string
  verifiers?: Verifiers
  resolver?: DIDResolver
  cache?: DIDCache
  methods?: MethodRegistry
  /** See `VerifyTokenOptions.historic`. Defaults to `false` — the issuer's current keys only. */
  historic?: boolean
}

/**
 * Verify the signature of a signed payload and return the public key of the issuer.
 */
export async function verifySignedPayload<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(input: VerifySignedPayloadInput<Payload>): Promise<Uint8Array> {
  const { signature, payload, header, data, verifiers, resolver, cache, methods, historic } = input
  assertType(validateSignedPayload, payload)
  const effectiveResolver: DIDResolver | undefined =
    cache == null
      ? resolver
      : async (did) => {
          const cached = await cache.get(did)
          if (cached != null) return cached
          return resolver != null ? resolver(did) : undefined
        }
  const { alg, publicKey, peer4Doc } = await resolveIssuerWithDoc(
    payload.iss,
    { kid: header.kid },
    effectiveResolver,
    methods,
    { historic },
  )
  const verify = getVerifier(alg, verifiers)
  const message = typeof data === 'string' ? fromUTF(data) : data
  const verified = await verify(signature, message, publicKey)
  if (!verified) {
    throw new Error('Invalid signature')
  }
  if (cache != null && peer4Doc != null) {
    await cache.set(peer4Doc.shortForm, peer4Doc.doc)
  }
  return publicKey
}

/**
 * Check if a token is signed.
 */
export function isSignedToken<Payload extends SignedPayload = SignedPayload>(
  token: unknown,
): token is SignedToken<Payload> {
  if (typeof token !== 'object' || token === null) {
    return false
  }
  const t = token as SignedToken<Payload>
  return (
    isType(validateSignedHeader, t.header) &&
    isType(validateSignedPayload, t.payload) &&
    t.signature != null
  )
}

/**
 * Check if a token is unsigned.
 */
export function isUnsignedToken<Payload extends Record<string, unknown>>(
  token: unknown,
): token is UnsignedToken<Payload> {
  if (typeof token !== 'object' || token === null) {
    return false
  }
  return isType(validateUnsignedHeader, (token as UnsignedToken<Payload>).header)
}

/**
 * Check if a token was verified by `verifyToken` in this process.
 * A `verifiedPublicKey` property on a deserialized token is never trusted.
 */
export function isVerifiedToken<Payload extends SignedPayload>(
  token: unknown,
): token is VerifiedToken<Payload> {
  return (
    isSignedToken(token) &&
    (token as VerifiedToken<Payload>).verifiedPublicKey != null &&
    verifiedTokens.has(token as object)
  )
}

/**
 * Create an unsigned token object.
 */
export function createUnsignedToken<
  Payload extends Record<string, unknown>,
  Header extends Record<string, unknown> = Record<string, unknown>,
>(payload: Payload, header?: Header): UnsignedToken<Payload, Header> {
  return { header: { ...(header ?? ({} as Header)), typ: 'JWT', alg: 'none' }, payload }
}

/**
 * Sign a token object if not already signed.
 */
export async function signToken<
  Payload extends Record<string, unknown>,
  Header extends Record<string, unknown>,
>(signer: SigningIdentity, token: Token<Payload, Header>): Promise<SignedToken<Payload, Header>> {
  return isSignedToken(token)
    ? (token as SignedToken<Payload, Header>)
    : ((await signer.signToken(token.payload, { header: token.header })) as SignedToken<
        Payload,
        Header
      >)
}

// Whether `data` is a serialization of the token's current header and payload. It may use a
// different JSON serialization of the same values; accept it only if it decodes to exactly those,
// so the signed bytes can never be decoupled from the payload used for authorization.
function matchesVerifiableData(token: SignedToken<Record<string, unknown>>, data: string): boolean {
  if (data === `${b64uFromJSON(token.header)}.${b64uFromJSON(token.payload)}`) {
    return true
  }
  const parts = data.split('.')
  if (parts.length !== 2) {
    return false
  }
  try {
    return (
      canonicalStringify(b64uToJSON(parts[0])) === canonicalStringify(token.header) &&
      canonicalStringify(b64uToJSON(parts[1])) === canonicalStringify(token.payload)
    )
  } catch {
    // invalid base64url or JSON in data
    return false
  }
}

function getVerifiableData(token: SignedToken<Record<string, unknown>>): string {
  const data = token.data
  if (data == null) {
    return `${b64uFromJSON(token.header)}.${b64uFromJSON(token.payload)}`
  }
  if (typeof data === 'string' && matchesVerifiableData(token, data)) {
    return data
  }
  throw new Error('Invalid token: data does not match header and payload')
}

// Re-bind an already-verified token to the bytes its signature was checked against. The `data`
// comes from `verifiedTokenData`, never from the token, so a caller that mutates the payload
// cannot make the check pass by re-deriving `token.data` alongside it.
function assertVerifiedDataUnchanged(token: SignedToken<Record<string, unknown>>): void {
  const data = verifiedTokenData.get(token)
  if (data == null || !matchesVerifiableData(token, data)) {
    throw new Error('Invalid token: data does not match header and payload')
  }
}

async function verifyTokenInner<Payload extends Record<string, unknown> = Record<string, unknown>>(
  token: Token<Payload> | string,
  options: VerifyTokenOptions = {},
): Promise<Token<Payload>> {
  const {
    verifiers,
    resolver,
    cache,
    methods,
    audience,
    allowUnsigned = false,
    historic,
    ...timeOptions
  } = options
  if (typeof token !== 'string') {
    if (isUnsignedToken(token)) {
      assertSignedForAudience(audience)
      assertUnsignedAllowed(allowUnsigned)
      assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
      return token
    }
    // The `historic` arm is what keeps the fast path from weakening the check: a token verified
    // against a rotated-away key must not satisfy a later caller who asked for the issuer's current
    // keys. It falls through to the full verification below rather than being rejected.
    if (isVerifiedToken(token) && !(historic !== true && historicallyVerifiedTokens.has(token))) {
      // The signature was checked when this object entered `verifiedTokens`, but its payload may
      // have been mutated in place since. Re-bind it to the signed bytes — cheap next to a
      // signature verification, and enough to reject tampering.
      assertVerifiedDataUnchanged(token)
      assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
      assertAudienceValid(token.payload as Record<string, unknown>, audience)
      return token
    }
    if (isSignedToken(token)) {
      const data = getVerifiableData(token)
      const verifiedPublicKey = await verifySignedPayload({
        signature: fromB64U(token.signature),
        payload: token.payload,
        header: token.header as { alg?: string; kid?: string },
        data,
        verifiers,
        resolver,
        cache,
        methods,
        historic,
      })
      assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
      assertAudienceValid(token.payload as Record<string, unknown>, audience)
      const result = { ...token, data, verifiedPublicKey } as Token<Payload>
      verifiedTokens.add(result)
      verifiedTokenData.set(result, data)
      if (historic === true) {
        historicallyVerifiedTokens.add(result)
      }
      return result
    }
    throw new Error('Unsupported token')
  }

  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new Error('Invalid token format: expected 3 parts separated by dots')
  }
  const [encodedHeader, encodedPayload, signature] = parts

  const header = b64uToJSON(encodedHeader)
  if (header.typ !== 'JWT') {
    throw new Error('Invalid token header type')
  }
  if (header.alg === 'none') {
    assertSignedForAudience(audience)
    assertUnsignedAllowed(allowUnsigned)
    const payload = b64uToJSON<Payload>(encodedPayload)
    assertTimeClaimsValid(payload as Record<string, unknown>, timeOptions)
    return { header, payload } as UnsignedToken<Payload>
  }

  if (isType(validateAlgorithm, header.alg)) {
    if (signature == null) {
      throw new Error('Missing signature for token with signed header')
    }

    const payload = b64uToJSON<Payload>(encodedPayload)
    const data = `${encodedHeader}.${encodedPayload}`
    const verifiedPublicKey = await verifySignedPayload({
      signature: fromB64U(signature),
      payload,
      header: header as { alg?: string; kid?: string },
      data,
      verifiers,
      resolver,
      cache,
      methods,
      historic,
    })
    assertTimeClaimsValid(payload as Record<string, unknown>, timeOptions)
    assertAudienceValid(payload as Record<string, unknown>, audience)
    const result = {
      data,
      header,
      payload,
      signature,
      verifiedPublicKey,
    } as Token<Payload>
    verifiedTokens.add(result)
    verifiedTokenData.set(result, data)
    if (historic === true) {
      historicallyVerifiedTokens.add(result)
    }
    return result
  }

  throw new Error('Unsupported signature algorithm')
}

/**
 * Verify a token is either unsigned or signed with a valid signature.
 * Also validates time-based claims (exp, nbf) if present.
 */
export async function verifyToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(
  token: Token<Payload> | string,
  options?: VerifyTokenOptions & { allowUnsigned?: false },
): Promise<VerifiedToken<Payload>>
export async function verifyToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(
  token: Token<Payload> | string,
  options: VerifyTokenOptions & { allowUnsigned: true },
): Promise<Token<Payload>>
export async function verifyToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(token: Token<Payload> | string, options: VerifyTokenOptions): Promise<Token<Payload>>
export async function verifyToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(token: Token<Payload> | string, options: VerifyTokenOptions = {}): Promise<Token<Payload>> {
  return withSpan(tokenTracer, KokuinSpanNames.TOKEN_VERIFY, {}, async (span) => {
    const result = await verifyTokenInner(token, options)
    if (isSignedToken(result)) {
      span.setAttribute(
        KokuinAttributeKeys.AUTH_DID,
        (result.payload as Record<string, unknown>).iss as string,
      )
      span.setAttribute(KokuinAttributeKeys.AUTH_ALGORITHM, result.header.alg)
    }
    return result
  })
}
