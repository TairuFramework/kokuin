import { nobleCrypto } from '@kokuin/crypto'
import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import {
  b64uFromJSON,
  b64uToJSON,
  canonicalStringify,
  fromB64U,
  fromUTF,
  toB64U,
} from '@sozai/codec'
import { withSpan } from '@sozai/otel'
import { assertType, isType } from '@sozai/schema'

import type { DIDCache, DIDResolver } from './cache.js'
import { resolveIssuerWithDoc } from './did.js'
import type { CryptoOptions, SigningIdentity } from './identity.js'
import type { DIDMethodResolver, MethodRegistry } from './method.js'
import {
  type SignatureAlgorithm,
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

function captureMethods(methods?: MethodRegistry): MethodRegistry | undefined {
  return methods?.map((method) => {
    return {
      ...method,
      method: method.method,
      resolve: method.resolve.bind(method),
      resolveHistoric: method.resolveHistoric?.bind(method),
    }
  })
}

type MethodPolicy = Pick<DIDMethodResolver, 'method' | 'resolve' | 'resolveHistoric'> & {
  source: DIDMethodResolver
}

type VerificationPolicy = {
  crypto: NonNullable<CryptoOptions['crypto']>
  verifiers: Verifiers
  resolver: DIDResolver | undefined
  cache: DIDCache | undefined
  methods: MethodRegistry | undefined
  methodPolicy: Array<MethodPolicy> | undefined
  cacheGet: DIDCache['get'] | undefined
  cacheSet: DIDCache['set'] | undefined
}
type Provenance = {
  policy: VerificationPolicy
  alg: SignatureAlgorithm
  signature: string
  publicKey: string
}
const provenance = new WeakMap<object, Provenance>()

function capturePolicy(options: VerifyTokenOptions): VerificationPolicy {
  return {
    crypto: options.crypto ?? nobleCrypto,
    verifiers: { ...options.verifiers },
    resolver: options.resolver,
    cache: options.cache,
    methods: captureMethods(options.methods),
    methodPolicy: options.methods?.map((method) => {
      return {
        source: method,
        method: method.method,
        resolve: method.resolve,
        resolveHistoric: method.resolveHistoric,
      }
    }),
    cacheGet: options.cache?.get,
    cacheSet: options.cache?.set,
  }
}

function samePolicy(known: Provenance, policy: VerificationPolicy): boolean {
  const prior = known.policy
  return (
    prior.crypto === policy.crypto &&
    prior.verifiers[known.alg] === policy.verifiers[known.alg] &&
    prior.resolver === policy.resolver &&
    prior.cache === policy.cache &&
    prior.cacheGet === policy.cacheGet &&
    prior.cacheSet === policy.cacheSet &&
    (prior.methodPolicy?.length ?? 0) === (policy.methodPolicy?.length ?? 0) &&
    (prior.methodPolicy ?? []).every((method, index) => {
      const next = policy.methodPolicy?.[index]
      return (
        next !== undefined &&
        method.source === next.source &&
        method.method === next.method &&
        method.resolve === next.resolve &&
        method.resolveHistoric === next.resolveHistoric
      )
    })
  )
}

export type VerifyTokenOptions = TimeValidationOptions &
  CryptoOptions & {
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
> = CryptoOptions & {
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
async function verifySignedPayloadWithPolicy<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(
  input: VerifySignedPayloadInput<Payload>,
): Promise<{ publicKey: Uint8Array; alg: SignatureAlgorithm }> {
  const { payload, header, resolver, historic } = input
  const sourceCache = input.cache
  const cache =
    sourceCache == null
      ? undefined
      : {
          get: sourceCache.get.bind(sourceCache),
          set: sourceCache.set.bind(sourceCache),
        }
  const signature = new Uint8Array(input.signature)
  const message = typeof input.data === 'string' ? fromUTF(input.data) : new Uint8Array(input.data)
  const verifiers = { ...input.verifiers }
  const methods = captureMethods(input.methods)
  const crypto = input.crypto ?? nobleCrypto
  assertType(validateSignedPayload, payload)
  const effectiveResolver: DIDResolver | undefined =
    cache == null
      ? resolver
      : async (did) => {
          const cached = await cache.get(did)
          if (cached != null) return cached
          return resolver != null ? resolver(did) : undefined
        }
  const { alg, publicKey, peer4Doc } = await resolveIssuerWithDoc({
    iss: payload.iss,
    header: { kid: header.kid },
    resolver: effectiveResolver,
    methods,
    historic,
  })
  const verify = getVerifier(alg, verifiers, { crypto })
  const key = new Uint8Array(publicKey)
  const verified = await verify(signature, message, key)
  if (!verified) {
    throw new Error('Invalid signature')
  }
  if (cache != null && peer4Doc != null) {
    await cache.set(peer4Doc.shortForm, peer4Doc.doc)
  }
  return { publicKey: key, alg }
}

export async function verifySignedPayload<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(input: VerifySignedPayloadInput<Payload>): Promise<Uint8Array> {
  return (await verifySignedPayloadWithPolicy(input)).publicKey
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
  const [headerPart, payloadPart, extra] = data.split('.')
  if (headerPart === undefined || payloadPart === undefined || extra !== undefined) {
    return false
  }
  try {
    return (
      canonicalStringify(b64uToJSON(headerPart)) === canonicalStringify(token.header) &&
      canonicalStringify(b64uToJSON(payloadPart)) === canonicalStringify(token.payload)
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
  const policy = capturePolicy(options)
  const {
    crypto,
    verifiers,
    resolver,
    cache,
    methods,
    audience: inputAudience,
    allowUnsigned = false,
    historic,
    methodPolicy: _methodPolicy,
    cacheGet: _cacheGet,
    cacheSet: _cacheSet,
    ...timeOptions
  } = { ...options, ...policy }
  const audience = Array.isArray(inputAudience) ? inputAudience.slice() : inputAudience
  if (typeof token !== 'string') {
    if (isUnsignedToken(token)) {
      assertSignedForAudience(audience)
      assertUnsignedAllowed(allowUnsigned)
      assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
      return token
    }
    if (isVerifiedToken(token)) assertVerifiedDataUnchanged(token)
    const known = typeof token === 'object' ? provenance.get(token) : undefined
    // The `historic` arm is what keeps the fast path from weakening the check: a token verified
    // against a rotated-away key must not satisfy a later caller who asked for the issuer's current
    // keys. It falls through to the full verification below rather than being rejected.
    if (
      isVerifiedToken(token) &&
      known !== undefined &&
      samePolicy(known, policy) &&
      known.signature === token.signature &&
      known.publicKey === toB64U(token.verifiedPublicKey) &&
      !(historic !== true && historicallyVerifiedTokens.has(token))
    ) {
      assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
      assertAudienceValid(token.payload as Record<string, unknown>, audience)
      return token
    }
    if (isSignedToken(token)) {
      const data = getVerifiableData(token)
      const [headerPart, payloadPart] = data.split('.')
      if (headerPart === undefined || payloadPart === undefined)
        throw new Error('Invalid token data')
      const snapshot = {
        ...token,
        header: b64uToJSON(headerPart),
        payload: b64uToJSON<Payload>(payloadPart),
      }
      const { publicKey: verifiedPublicKey, alg } = await verifySignedPayloadWithPolicy({
        signature: fromB64U(snapshot.signature),
        payload: snapshot.payload,
        header: snapshot.header as { alg?: string; kid?: string },
        data,
        crypto,
        verifiers,
        resolver,
        cache,
        methods,
        historic,
      })
      assertTimeClaimsValid(snapshot.payload as Record<string, unknown>, timeOptions)
      assertAudienceValid(snapshot.payload as Record<string, unknown>, audience)
      const result = { ...snapshot, data, verifiedPublicKey } as Token<Payload>
      verifiedTokens.add(result)
      verifiedTokenData.set(result, data)
      provenance.set(result, {
        policy,
        alg,
        signature: snapshot.signature,
        publicKey: toB64U(verifiedPublicKey),
      })
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
  if (encodedHeader === undefined || encodedPayload === undefined) {
    throw new Error('Invalid token format: expected 3 parts separated by dots')
  }

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
    const { publicKey: verifiedPublicKey, alg } = await verifySignedPayloadWithPolicy({
      signature: fromB64U(signature),
      payload,
      header: header as { alg?: string; kid?: string },
      data,
      crypto,
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
    provenance.set(result, { policy, alg, signature, publicKey: toB64U(verifiedPublicKey) })
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
