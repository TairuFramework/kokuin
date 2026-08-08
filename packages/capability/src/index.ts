/**
 * Capability delegation and verification for JWTs.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/capability
 * ```
 *
 * @module capability
 */

import {
  type DIDCache,
  type DIDResolver,
  isVerifiedToken,
  normalizeDID,
  type SignedHeader,
  type SignedPayload,
  type SignedToken,
  type SigningIdentity,
  verifyToken,
} from '@kokuin/token'

export function now(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * Maximum delegation links an offline verifier will walk.
 *
 * Four: management → device → connector is three, plus one of headroom. Lowered from 20 —
 * lowering the default can only reject chains, never accept new ones, and `maxDepth` stays
 * overridable per call for anything that legitimately needs more.
 */
export const DEFAULT_MAX_DELEGATION_DEPTH = 4

/**
 * Default ceiling on a device capability's lifetime.
 *
 * The expiry length *is* the accepted-loss window at an offline verifier: revocation reaches it
 * best-effort, an unrenewed expiry is unconditional. On-log revocation narrows the window but
 * does not remove it, so pick this by how many days of a thief writing as the victim is
 * acceptable — not by renewal convenience.
 */
export const DEFAULT_MAX_DEVICE_LIFETIME_SECONDS = 7 * 24 * 60 * 60

/** Hook called for each token during verification. Throw to reject. */
export type VerifyTokenHook = (token: CapabilityToken, raw: string) => void | Promise<void>

/** Options for delegation chain validation */
export type DelegationChainOptions = {
  /** Time to use for expiration checks (seconds since epoch). Defaults to now(). */
  atTime?: number
  /** Maximum depth of delegation chain. Defaults to {@link DEFAULT_MAX_DELEGATION_DEPTH}. */
  maxDepth?: number
  /** Optional hook called for each token in the chain after verification. Can be used for revocation checks. */
  verifyToken?: VerifyTokenHook
  /** Optional DID cache for resolving did:peer:4 issuers. Populated on long-form first contact. */
  cache?: DIDCache
  /** Optional resolver for did:peer:4 short forms not in cache. */
  resolver?: DIDResolver
}

/** Options for capability creation */
export type CreateCapabilityOptions = {
  /**
   * Parent capability token (stringified) that authorizes this delegation.
   * Required when creating a capability where signer is not the subject.
   * The signer must be the audience of the parent capability.
   */
  parentCapability?: string
}

export type Permission = {
  act: string | Array<string>
  res: string | Array<string>
}

export type CapabilityPayload = Permission & {
  iss: string
  sub: string
  aud: string
  exp?: number
  iat?: number
  jti?: string
}

export type CapabilityToken<
  Payload extends CapabilityPayload = CapabilityPayload,
  Header extends Record<string, unknown> = Record<string, unknown>,
> = SignedToken<Payload, Header>

function isStringOrStringArray(value: unknown): value is string | Array<string> {
  if (typeof value === 'string') {
    return true
  }
  if (Array.isArray(value)) {
    return value.every((item) => typeof item === 'string')
  }
  return false
}

// Valid pattern: alphanumeric, hyphens, underscores, dots, colons, slashes, and trailing wildcard
// Components are separated by '/'. Wildcard '*' is only valid as the entire last component.
const VALID_COMPONENT_RE = /^[a-zA-Z0-9_\-.:]+$/
// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional check for control characters
const CONTROL_CHAR_RE = /[\x00-\x1f]/

export function assertValidPattern(value: string | Array<string>): void {
  if (Array.isArray(value)) {
    for (const v of value) {
      assertValidPattern(v)
    }
    return
  }

  if (value === '*') {
    return
  }

  if (value === '') {
    throw new Error('Invalid pattern: empty string')
  }

  if (CONTROL_CHAR_RE.test(value)) {
    throw new Error('Invalid pattern: contains control characters')
  }

  if (value.startsWith('/') || value.endsWith('/')) {
    throw new Error('Invalid pattern: leading or trailing slash')
  }

  if (value.includes('//')) {
    throw new Error('Invalid pattern: double slash')
  }

  if (value.includes('../') || value.includes('./')) {
    throw new Error('Invalid pattern: path traversal')
  }

  const parts = value.split('/')
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]
    if (part === '*') {
      if (i !== parts.length - 1) {
        throw new Error('Invalid pattern: wildcard must be the last component')
      }
    } else if (part.includes('*')) {
      throw new Error('Invalid pattern: wildcard must be a standalone component')
    } else if (!VALID_COMPONENT_RE.test(part)) {
      throw new Error('Invalid pattern: invalid characters')
    }
  }
}

export function isCapabilityToken<Payload extends CapabilityPayload>(
  token: unknown,
): token is CapabilityToken<Payload> {
  if (!isVerifiedToken(token)) {
    return false
  }

  const payload = token.payload as Record<string, unknown>

  // Validate required string fields
  if (typeof payload.iss !== 'string') {
    return false
  }
  if (typeof payload.aud !== 'string') {
    return false
  }
  if (typeof payload.sub !== 'string') {
    return false
  }

  // Validate act and res are string or string[]
  if (!isStringOrStringArray(payload.act)) {
    return false
  }
  if (!isStringOrStringArray(payload.res)) {
    return false
  }

  return true
}

export function assertCapabilityToken<Payload extends CapabilityPayload>(
  token: unknown,
): asserts token is CapabilityToken<Payload> {
  if (!isCapabilityToken(token)) {
    throw new Error('Invalid token: not a capability')
  }
}

export type SignCapabilityPayload = Omit<CapabilityPayload, 'iss'> & { iss?: string }

export async function createCapability<
  Payload extends SignCapabilityPayload = SignCapabilityPayload,
>(
  signer: SigningIdentity,
  payload: Payload,
  header?: Record<string, unknown>,
  options?: CreateCapabilityOptions,
): Promise<CapabilityToken<Payload & { iss: string }, SignedHeader>> {
  const signerID = signer.id

  // Validate act/res patterns
  assertValidPattern(payload.act)
  assertValidPattern(payload.res)

  // If signer is the subject, no parent validation needed (root capability)
  if (normalizeDID(payload.sub) === normalizeDID(signerID)) {
    return await signer.signToken(payload, { header })
  }

  // Signer is delegating on behalf of someone else - validate authorization
  if (options?.parentCapability == null) {
    throw new Error(
      'Invalid capability: parentCapability required when delegating for another subject',
    )
  }

  // Verify and validate the parent capability
  const parent = await verifyToken<CapabilityPayload>(options.parentCapability)
  assertCapabilityToken(parent)

  if (normalizeDID(parent.payload.aud) !== normalizeDID(signerID)) {
    throw new Error('Invalid capability: signer must be the audience of parent capability')
  }

  if (normalizeDID(parent.payload.sub) !== normalizeDID(payload.sub)) {
    throw new Error('Invalid capability: subject mismatch with parent capability')
  }

  // Check parent is not expired
  assertNonExpired(parent.payload)

  // Check that the new capability doesn't exceed parent permissions
  const newPermission: Permission = {
    act: payload.act,
    res: payload.res,
  }
  const parentPermission: Permission = {
    act: parent.payload.act,
    res: parent.payload.res,
  }

  if (!hasPermission(newPermission, parentPermission)) {
    throw new Error('Invalid capability: delegated permission exceeds parent capability')
  }

  return await signer.signToken(payload, { header })
}

export function isMatch(expected: string, actual: string): boolean {
  return expected === actual || actual === '*'
}

// `expected` is the requested permission, `actual` the granted one. A grant authorizes a
// request only when the grant's segments match the request's segment-for-segment at the same
// depth, with a `*` grant segment matching the remainder. A grant more specific than the
// request (e.g. `foo/bar/baz` vs requested `foo/bar`) does NOT authorize it — that broadening
// was the privilege-escalation bug. There is no implicit descent either: `foo/bar` does not
// cover `foo/bar/baz`; use `foo/bar/*` for that.
export function hasPartsMatch(expected: string, actual: string): boolean {
  const expectedParts = expected.split('/')
  const actualParts = actual.split('/')
  for (let i = 0; i < actualParts.length; i++) {
    const grantPart = actualParts[i]
    if (grantPart === '*') {
      return true
    }
    // Grant has a segment the request does not: the grant is more specific than the
    // request, so it must not authorize the broader request.
    if (i >= expectedParts.length) {
      return false
    }
    if (grantPart !== expectedParts[i]) {
      return false
    }
  }
  // All grant segments matched; authorize only when the request is no deeper than the grant.
  return expectedParts.length === actualParts.length
}

export function hasPermission(expected: Permission, granted: Permission): boolean {
  // If multiple actions are expected, check that all of them are granted
  if (Array.isArray(expected.act)) {
    return expected.act.every((act) => hasPermission({ act, res: expected.res }, granted))
  }
  // If multiple resources are expected, check that all of them are granted
  if (Array.isArray(expected.res)) {
    return expected.res.every((res) => hasPermission({ act: expected.act, res }, granted))
  }
  // If multiple actions are granted, check that at least one of them matches the expectation
  if (Array.isArray(granted.act)) {
    return granted.act.some((act) => hasPermission(expected, { act, res: granted.res }))
  }
  // If multiple resource are granted, check that at least one of them matches the expectation
  if (Array.isArray(granted.res)) {
    return granted.res.some((res) => hasPermission(expected, { act: granted.act, res }))
  }
  // Sanity check
  if (granted.act === '' || granted.res === '') {
    return false
  }
  // Check for exact or wildcard match of the action and resource
  if (isMatch(expected.act, granted.act) && isMatch(expected.res, granted.res)) {
    return true
  }
  // Check for partial match of the action and resource
  return hasPartsMatch(expected.act, granted.act) && hasPartsMatch(expected.res, granted.res)
}

export function assertNonExpired(payload: { exp?: number }, atTime?: number): void {
  if (payload.exp != null && payload.exp < (atTime ?? now())) {
    throw new Error('Invalid token: expired')
  }
}

export type DeviceCapabilityPolicyOptions = {
  maxLifetimeSeconds?: number
  now?: number
}

/**
 * Enforce that a device capability sets a bounded expiry.
 *
 * `exp` is optional in the capability schema and `assertNonExpired` only enforces it when
 * present, so the schema will never require it. Mint and verify paths for device capabilities
 * must call this.
 */
export function assertDeviceCapabilityPolicy(
  payload: { exp?: number },
  options: DeviceCapabilityPolicyOptions = {},
): void {
  const atTime = options.now ?? now()
  const maxLifetime = options.maxLifetimeSeconds ?? DEFAULT_MAX_DEVICE_LIFETIME_SECONDS
  if (payload.exp == null) {
    throw new Error('CapabilityError.PolicyViolation: device capabilities must set exp')
  }
  assertNonExpired(payload, atTime)
  if (payload.exp - atTime > maxLifetime) {
    throw new Error(
      `CapabilityError.PolicyViolation: device capability lifetime exceeds ${maxLifetime}s`,
    )
  }
}

export function assertValidIssuedAt(payload: { iat?: number }, atTime?: number): void {
  if (payload.iat != null && payload.iat > (atTime ?? now())) {
    throw new Error('Invalid token: issued in the future')
  }
}

export function assertValidDelegation(
  from: CapabilityPayload,
  to: CapabilityPayload,
  atTime?: number,
): void {
  const time = atTime ?? now()
  if (normalizeDID(to.iss) !== normalizeDID(from.aud)) {
    throw new Error('Invalid capability: audience mismatch')
  }
  if (normalizeDID(to.sub) !== normalizeDID(from.sub)) {
    throw new Error('Invalid capability: subject mismatch')
  }
  assertNonExpired(from, time)
  assertValidIssuedAt(from, time)
  if (!hasPermission(to, from)) {
    throw new Error('Invalid capability: permission mismatch')
  }
}

export async function checkDelegationChain(
  payload: CapabilityPayload,
  capabilities: Array<string>,
  options?: DelegationChainOptions,
): Promise<void> {
  const maxDepth = options?.maxDepth ?? DEFAULT_MAX_DELEGATION_DEPTH
  const atTime = options?.atTime ?? now()

  if (capabilities.length > maxDepth) {
    throw new Error(`Invalid capability: delegation chain exceeds maximum depth of ${maxDepth}`)
  }

  if (capabilities.length === 0) {
    if (normalizeDID(payload.iss) !== normalizeDID(payload.sub)) {
      throw new Error('Invalid capability: issuer should be subject')
    }
    assertNonExpired(payload, atTime)
    assertValidIssuedAt(payload, atTime)
    return
  }

  const [head, ...tail] = capabilities
  // Verify the leaf capability's own time claims (exp/nbf) at the same reference
  // time used for the delegation checks, so a capability that was valid when the
  // request was issued is not rejected by a later wall-clock during verification.
  const next = await verifyToken<CapabilityPayload>(head, {
    atTime,
    cache: options?.cache,
    resolver: options?.resolver,
  })
  assertCapabilityToken(next)
  if (options?.verifyToken != null) {
    await options.verifyToken(next, head)
  }
  assertValidDelegation(next.payload, payload, atTime)
  await checkDelegationChain(next.payload, tail, { ...options, atTime })
}

export async function checkCapability(
  permission: Permission,
  payload: SignedPayload,
  options?: DelegationChainOptions,
): Promise<void> {
  if (payload.sub == null) {
    throw new Error('Invalid payload: no subject')
  }

  const time = options?.atTime ?? now()
  if (normalizeDID(payload.iss) === normalizeDID(payload.sub)) {
    // Subject is issuer, no delegation required
    // But still need to validate the permission is granted
    assertNonExpired(payload, time)
    assertValidIssuedAt(payload as { iat?: number }, time)

    // Validate that the token grants the requested permission
    const p = payload as Record<string, unknown>
    const act = p.act as string | Array<string> | undefined
    const res = p.res as string | Array<string> | undefined

    if (act == null || res == null) {
      throw new Error('Invalid payload: missing act or res for self-issued token')
    }

    if (!hasPermission(permission, { act, res })) {
      throw new Error('Invalid capability: permission not granted')
    }

    return
  }

  if (payload.cap == null) {
    throw new Error('Invalid payload: no capability')
  }

  const [head, ...tail] = Array.isArray(payload.cap) ? payload.cap : [payload.cap]
  if (head == null) {
    throw new Error('Invalid payload: no capability')
  }
  // Verify the leaf capability's own time claims at the resolved reference time
  // (`atTime` when provided, else now()), matching the delegation checks below.
  const capability = await verifyToken<CapabilityPayload>(head, {
    atTime: time,
    cache: options?.cache,
    resolver: options?.resolver,
  })
  assertCapabilityToken(capability)
  if (options?.verifyToken != null) {
    await options.verifyToken(capability, head)
  }

  const toCapability = { ...payload, ...permission } as CapabilityPayload
  assertValidDelegation(capability.payload, toCapability, time)
  await checkDelegationChain(capability.payload, tail, { ...options, atTime: time })
}

export type { RevocationBackend, RevocationRecord } from './revocation.js'
export {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
} from './revocation.js'
