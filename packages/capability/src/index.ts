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
  findMethodResolver,
  isVerifiedToken,
  type MethodRegistry,
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
  /**
   * Optional DID method registry, forwarded to `verifyToken` for every capability in the chain.
   * Required when any link is issued by a method that cannot be resolved from the identifier
   * alone, such as `did:kokuin:`.
   */
  methods?: MethodRegistry
}

/** Options for capability creation */
export type CreateCapabilityOptions = {
  /**
   * Parent capability token (stringified) that authorizes this delegation.
   * Required when creating a capability where signer is not the subject.
   * The signer must be the audience of the parent capability.
   */
  parentCapability?: string
  /** Optional DID cache for resolving did:peer:4 issuers. Populated on long-form first contact. */
  cache?: DIDCache
  /** Optional resolver for did:peer:4 short forms not in cache. */
  resolver?: DIDResolver
  /**
   * Optional DID method registry, forwarded to `verifyToken` when verifying the parent
   * capability. Required when the parent is issued by a method that cannot be resolved from the
   * identifier alone, such as `did:kokuin:` — the same reason `DelegationChainOptions` carries
   * it for every other link in a chain. A parent issued by a `did:peer:4` short form has the
   * identical resolution problem, so `cache` and `resolver` travel with it here too, rather than
   * leaving this one call site one option short of its neighbours.
   */
  methods?: MethodRegistry
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
  /**
   * Proof-of-possession key the audience must hold, pinned at mint time. See
   * {@link ConfirmationClaim}.
   *
   * Optional in general: a capability whose holder proves itself by signing a token needs nothing
   * here, since the token names its own issuer. It is **required** by
   * `createControllerCapabilityVerifier`, where the holder proves itself by signing a raw key
   * event that names nobody, and where resolving the audience instead would let that audience's
   * own key rotation make the profile unresolvable forever.
   */
  cnf?: ConfirmationClaim
}

/**
 * RFC 7800's `cnf` (confirmation) claim: the key the presenter of this token must prove possession
 * of. The registered claim for exactly this job, so the wire format is a standard one rather than
 * a house invention — worth getting right before anything publishes, since wire format is the
 * hardest thing to change afterwards.
 *
 * The member is `kid` rather than `jwk`. RFC 7800 §3.4 leaves `kid`'s content application-specific
 * and expects the recipient to be able to turn it into a key; here the identifier **is** the key —
 * a multicodec-tagged, multibase-encoded public key, self-describing and requiring no lookup —
 * which is the same `kid` convention `did:kokuin:` already fixed for token headers, and the same
 * encoding a controller log uses for the keys in `k`. `cnf.jwk` is the strictly by-value member and
 * would be defensible, but it would put a second encoding of the same key next to the one this
 * stack already has, add JWK serialisation and canonical comparison to a package with neither, and
 * buy nothing that the tagged multibase form does not already carry.
 *
 * Only `kid` is understood. Any other member — including a legitimate RFC 7800 `jwk`, `jwe` or
 * `jku` — fails closed rather than being resolved, because resolving is the bug this claim exists
 * to remove. The type stays open so that carrying one is a typing question rather than a cast: the
 * claim's extensibility has to be real in the type, not only on the wire, or "add `jwk` alongside
 * later" is a promise TypeScript will not let a caller keep.
 */
export type ConfirmationClaim = { kid?: string; [member: string]: unknown }

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
  const parent = await verifyToken<CapabilityPayload>(options.parentCapability, {
    cache: options.cache,
    resolver: options.resolver,
    methods: options.methods,
  })
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

/**
 * Reject a token that is not yet valid.
 *
 * The third registered time claim, and the one this package had no check for. `verifyToken` enforces
 * it on every token it verifies, so a chain link is covered — but a payload handed straight to
 * `checkCapability` never passes through `verifyToken` here, and `exp` and `iat` were the only two
 * such a payload was checked for.
 */
export function assertValidNotBefore(payload: { nbf?: number }, atTime?: number): void {
  if (payload.nbf != null && payload.nbf > (atTime ?? now())) {
    throw new Error('Invalid token: not yet valid')
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

/**
 * What a capability the subject has revoked its audience is rejected with. The audience DID is
 * appended, so a caller matching on this constant should use `startsWith` rather than equality.
 */
export const AUDIENCE_REVOKED = 'Invalid capability: audience is revoked by the subject'

/**
 * Reject a capability whose audience the subject has revoked.
 *
 * The subject of a capability is the party whose resources it grants, and a `did:kokuin:` subject
 * publishes a deny set in its own key event log: "no capability whose `aud` is that DID is valid
 * from this position onward". Nothing else in this stack turns that set into a denial — the log is
 * a `@kokuin/controller` concern and this package cannot import it without a cycle — so the rule
 * travels through `DIDMethodResolver.resolveDenySet` on the registry callers already pass for
 * resolution.
 *
 * Evaluated against the subject's **current** state, never against a position the capability names:
 * `iat` is author-supplied and backdatable, so a holder could otherwise choose a moment before it
 * was revoked.
 *
 * Silent when the subject's method publishes no deny set, and when no registry was supplied at all
 * — a subject that needs one is a subject `verifyToken` could not have resolved either, so the
 * chain has already failed by then. A resolver that *has* a deny set and cannot produce it throws,
 * which fails the chain closed.
 */
async function assertAudienceNotRevoked(
  payload: { sub?: unknown; aud?: unknown },
  options?: DelegationChainOptions,
): Promise<void> {
  const { sub, aud } = payload
  if (options?.methods == null || typeof sub !== 'string' || typeof aud !== 'string') {
    return
  }
  const resolveDenySet = findMethodResolver(options.methods, sub)?.resolveDenySet
  if (resolveDenySet == null) {
    return
  }
  const denied = await resolveDenySet(sub)
  // Both spellings: a deny set names whatever the `rev` event wrote, which for a `did:peer:4`
  // device may be either form, while `aud` may arrive as the other one.
  if (denied.has(aud) || denied.has(normalizeDID(aud))) {
    throw new Error(`${AUDIENCE_REVOKED}: ${aud}`)
  }
}

/**
 * The grant a `checkCapability` payload makes on its own behalf, or `undefined` when it makes none.
 *
 * That payload is one of two things. An **invocation** names no permission of its own: its whole
 * authority is the chain in `cap`, and the request is what the leaf of that chain has to cover. A
 * **capability presented directly** carries the grant it was minted with — which is what
 * `createControllerCapabilityVerifier` hands over, because a key event carries the capability and no
 * invocation token to wrap it in. Only the second has claims of its own to enforce.
 *
 * `act` and `res` together are what tell the two apart: the pair every capability carries, and that
 * no invocation shape in this stack does (enkaku's names its procedure in `prc`, kubun's names
 * nothing). Dropping the pair is not an escape — a payload without it *is* an invocation, and an
 * invocation's request has always been checked against the leaf capability in `cap`.
 */
function presentedGrant(payload: SignedPayload): Permission | undefined {
  const { act, res } = payload as { act?: unknown; res?: unknown }
  if (!isStringOrStringArray(act) || !isStringOrStringArray(res)) {
    return undefined
  }
  return { act, res }
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

  // Every link passes through here as `payload` — the first parent on the way in from
  // `checkCapability`, and each further parent as the recursion walks up — so one call covers the
  // whole chain above the payload `checkCapability` was handed. A revoked *intermediate* is the
  // case a per-leaf check would miss. The audience of a capability presented directly to
  // `checkCapability` is below that walk and is checked there, not here.
  //
  // After the depth bound, not before: this one may fold a log, and the bound is what stops a
  // caller-supplied chain from deciding how much of that work happens.
  await assertAudienceNotRevoked(payload, options)

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
    methods: options?.methods,
  })
  assertCapabilityToken(next)
  if (options?.verifyToken != null) {
    await options.verifyToken(next, head)
  }
  assertValidDelegation(next.payload, payload, atTime)
  await checkDelegationChain(next.payload, tail, { ...options, atTime })
}

/**
 * Check that `payload` authorises `permission`.
 *
 * `payload` is either an invocation — a token naming the capabilities it invokes in `cap`, whose
 * authority is entirely that chain — or a capability presented directly, which carries a grant of
 * its own. The second is not the exotic case: a `did:kokuin:` revoke event names a capability and
 * has no invocation token to wrap it in, so `createControllerCapabilityVerifier` presents the
 * capability itself. See {@link presentedGrant} for how the two are told apart, and why an attacker
 * gains nothing by presenting one as the other.
 *
 * A presented capability's own claims bind exactly like any other link's: the request must be
 * within *its* grant and not merely within its parent's, and its audience is subject to the
 * subject's deny set. Checking only its ancestors made attenuation at the last hop a no-op and left
 * the deny set blind to the one party actually holding the capability.
 */
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
    assertValidNotBefore(payload as { nbf?: number }, time)
    assertValidIssuedAt(payload as { iat?: number }, time)
    // This branch never reaches `checkDelegationChain`, so it needs the audience check of its own.
    // It is also the shape `createControllerCapabilityVerifier` takes: an undelegated management
    // capability, minted by the profile for one of its own devices, is exactly `iss === sub`.
    await assertAudienceNotRevoked(payload, options)

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

  // The grant the payload makes on its own behalf, when it makes one. Checked before anything is
  // resolved or verified: it costs nothing, and a request outside the presented grant is refused
  // whatever its ancestors say.
  const grant = presentedGrant(payload)
  if (grant != null) {
    if (!hasPermission(permission, grant)) {
      throw new Error('Invalid capability: permission not granted')
    }
    // A presented capability's own time claims are checked nowhere else. It never passes through
    // `verifyToken` here — the caller verified it and handed over the payload — and the chain walk
    // below starts at its parent, so an expired, not-yet-valid or future-dated capability was
    // accepted on this arm at any reference time. The same three claims the `iss === sub` arm
    // above checks, at the same `time`, because the two arms differ in how authority is derived
    // and not in when a token is valid.
    assertNonExpired(payload, time)
    assertValidNotBefore(payload as { nbf?: number }, time)
    assertValidIssuedAt(payload as { iat?: number }, time)
  }

  if (payload.cap == null) {
    throw new Error('Invalid payload: no capability')
  }

  const [head, ...tail] = Array.isArray(payload.cap) ? payload.cap : [payload.cap]
  if (head == null) {
    throw new Error('Invalid payload: no capability')
  }
  // Count `head` against the bound here, because this entry point peels it off before
  // `checkDelegationChain` applies the bound to what is left. Without this the default of four
  // admits five links — one more than "maximum delegation links an offline verifier will walk"
  // says, and the extra one is free to an attacker who controls the chain's length. The bound
  // inside `checkDelegationChain` stays as it is: a direct caller passes the whole chain, so
  // there `capabilities.length` already is the link count.
  const maxDepth = options?.maxDepth ?? DEFAULT_MAX_DELEGATION_DEPTH
  if (tail.length + 1 > maxDepth) {
    throw new Error(`Invalid capability: delegation chain exceeds maximum depth of ${maxDepth}`)
  }
  // Verify the leaf capability's own time claims at the resolved reference time
  // (`atTime` when provided, else now()), matching the delegation checks below.
  const capability = await verifyToken<CapabilityPayload>(head, {
    atTime: time,
    cache: options?.cache,
    resolver: options?.resolver,
    methods: options?.methods,
  })
  assertCapabilityToken(capability)
  if (options?.verifyToken != null) {
    await options.verifyToken(capability, head)
  }

  // The presented capability's audience is the party that actually holds it, and it is the one
  // audience the walk below never reaches — `checkDelegationChain` starts at the parent, whose
  // `aud` is the delegating party. Without this a device the subject has revoked keeps invoking
  // through one level of delegation. After the parent has verified, matching the reason the same
  // check sits after the depth bound in `checkDelegationChain`: resolving a deny set may fold a
  // log, and nothing a caller supplies should decide how much of that work happens.
  if (grant != null) {
    await assertAudienceNotRevoked(payload, options)
  }

  // Against its own grant when it has one: the parent has to cover what the presented capability
  // grants, not merely what this request asks for. The two together are the attenuation rule —
  // request within the grant, grant within the parent — and spreading `permission` over the payload
  // collapsed them into the second, discarding whatever narrowing the last hop applied.
  const toCapability = (
    grant == null ? { ...payload, ...permission } : payload
  ) as CapabilityPayload
  assertValidDelegation(capability.payload, toCapability, time)
  await checkDelegationChain(capability.payload, tail, { ...options, atTime: time })
}

// Re-exported so catching the fail-closed throw needs nothing but this package. `@kokuin/token`
// is a plain dependency here, not a peer, so a consumer without it would otherwise have to add a
// direct dependency on token to name the error — the very duplication that makes a cross-copy
// `instanceof` unreliable.
export {
  isUnresolvableIssuerError,
  UnresolvableIssuerError,
} from '@kokuin/token'

export type { CapabilityAuthorisation, ControllerCapabilityVerifier } from './controller.js'
export {
  audienceConfirmation,
  createControllerCapabilityVerifier,
  REVOKE_AUDIENCE_KEY_MISMATCH,
  REVOKE_NO_AUDIENCE_KEY,
  REVOKE_NO_POSITION,
  REVOKE_NOT_AUTHORISED,
} from './controller.js'
export type { RevocationBackend, RevocationOptions, RevocationRecord } from './revocation.js'
export {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
} from './revocation.js'
