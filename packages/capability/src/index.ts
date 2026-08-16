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

/**
 * Verify every capability against the keys its issuer held **at some point**, not only now
 * (`verifyToken`'s `historic` option). A capability is a past-minted artefact meant to keep working,
 * so for a rotating issuer (`did:kokuin:`) the "holds now" question would make a routine `rotate`
 * invalidate every capability the profile ever issued; the spec reserves that blast radius for
 * `reset`. What it costs: a leaked-and-rotated-away key's capability still verifies here — but it was
 * never a live proof of possession (the holder is `aud`, proven by the invocation signature or `cnf`
 * pin), and denying the key's *new* issuance is the default `resolve`, denying a holder the deny set.
 * A single constant so the three call sites cannot drift.
 */
const HISTORIC_ISSUANCE = true

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
   * Proof-of-possession key the audience must hold, pinned at mint time — see
   * {@link ConfirmationClaim}. Optional in general (a holder proving itself by signing a token needs
   * nothing here), but **required** by `createControllerCapabilityVerifier`, where the holder signs a
   * raw key event naming nobody and resolving the audience instead would let its key rotation brick
   * the profile.
   */
  cnf?: ConfirmationClaim
}

/**
 * RFC 7800's `cnf` (confirmation) claim: the key the presenter must prove possession of. The
 * registered claim for the job, so the wire format is standard rather than a house invention.
 *
 * The member is `kid`, not `jwk`: here the identifier **is** the key (multicodec-tagged multibase,
 * self-describing, no lookup) — the same `kid` convention `did:kokuin:` fixed for headers and the
 * encoding a controller log uses for `k`. `cnf.jwk` would add a second encoding, JWK serialisation,
 * and canonical comparison, buying nothing the tagged form does not.
 *
 * Only `kid` is understood; any other member (a legitimate `jwk`, `jwe`, `jku`) fails closed rather
 * than resolving, because resolving is the bug this claim removes. The type stays open so carrying
 * one is a typing question, not a cast — the extensibility has to be real in the type, not only wire.
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

// Valid component: alphanumeric, `-_.:#`. Components are '/'-separated; '*' wildcards only as a whole
// last component. `#` is here because a resource may be a key — a `did:kokuin:` `rev` names its
// target as a DID or `#<key>`, and `{ act: 'revoke', res: <target> }`. Without `#` the only grant
// that could revoke a key would be `res: '*'`, so "retire this one leaked key" would mean "revoke
// anything". `#` is inert to the matcher (components compared whole), so widening this set cannot
// invalidate an existing capability. Not a licence for arbitrary punctuation: each addition names the
// vocabulary that needs it.
const VALID_COMPONENT_RE = /^[a-zA-Z0-9_\-.:#]+$/
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
    // See {@link HISTORIC_ISSUANCE}. The parent was minted before this delegation exists at all.
    historic: HISTORIC_ISSUANCE,
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
 * Reject a token that is not yet valid — the third registered time claim. `verifyToken` enforces it
 * on every token it verifies, so a chain link is covered, but a payload handed straight to
 * `checkCapability` never passes through it and was checked only for `exp` and `iat`.
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
 * What a capability whose subject's deny set could not be consulted at all is rejected with. The
 * subject DID is appended, so match with `startsWith`.
 */
export const DENY_SET_UNAVAILABLE =
  'Invalid capability: no resolver for the subject, so its deny set cannot be checked'

/**
 * Whether a DID's identifier carries its own verification material, so no registry entry is required
 * and no deny set can be silently skipped. `did:key` **is** its key; `did:peer` is self-contained
 * (long form embeds the doc, short form hashes one) and neither has a deny set to miss. Every other
 * method resolves through the registry, where a deny set lives, so its absence means the question was
 * not asked. A prefix test, not a registry lookup: the point is to catch the caller who supplied *no*
 * registry, which asking the missing registry cannot do.
 */
function carriesOwnKeys(did: string): boolean {
  return did.startsWith('did:key:') || did.startsWith('did:peer:')
}

/**
 * Reject a capability whose audience the subject has revoked. A `did:kokuin:` subject publishes a
 * deny set in its own key event log ("no capability whose `aud` is that DID is valid from this
 * position onward"), and nothing else turns that set into a denial (importing the log would cycle),
 * so the rule travels through `DIDMethodResolver.resolveDenySet` on the registry.
 *
 * Evaluated against the subject's **current** state, never a position the capability names: `iat` is
 * backdatable, so a holder could otherwise pick a moment before it was revoked.
 *
 * Silent when the subject's method publishes no deny set. A resolver that *has* one and cannot
 * produce it throws (fails closed). **Not silent when no registry could answer for the subject at
 * all** — that once matched a chain (the root link is issued by the subject, needing the registry)
 * but not the `iss === sub` arm, where the caller verified the token itself, so a caller resolving a
 * `did:kokuin:` subject with their own resolver then omitting `methods` got no enforcement and no
 * indication. The subject's own method is the test (see {@link carriesOwnKeys}).
 *
 * The *holder* half of the set. `#<key>` entries denying the subject's own keys are enforced where a
 * key is resolved (`verifyToken` on every link), not here — this sees `aud`, not the signing key. The
 * two forms cannot collide, so membership matching stays exact.
 */
async function assertAudienceNotRevoked(
  payload: { sub?: unknown; aud?: unknown },
  options?: DelegationChainOptions,
): Promise<void> {
  const { sub, aud } = payload
  if (typeof sub !== 'string' || typeof aud !== 'string') {
    return
  }
  const resolver = options?.methods == null ? undefined : findMethodResolver(options.methods, sub)
  if (resolver == null) {
    if (carriesOwnKeys(sub)) {
      return
    }
    throw new Error(`${DENY_SET_UNAVAILABLE}: ${sub}`)
  }
  const { resolveDenySet } = resolver
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
 * The payload is either an **invocation** (no permission of its own; its authority is the `cap`
 * chain) or a **capability presented directly** (carries its minted grant — what
 * `createControllerCapabilityVerifier` hands over, a key event having no invocation to wrap it). Only
 * the second has claims to enforce. `act`+`res` tell them apart: every capability carries the pair,
 * no invocation shape here does. Dropping it is no escape — a payload without it *is* an invocation,
 * whose request is checked against the leaf in `cap`.
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

  // Every link passes through here as `payload`, so one call covers the whole chain above the payload
  // `checkCapability` was handed — a revoked *intermediate* is what a per-leaf check misses. After the
  // depth bound, not before: this may fold a log, and the bound stops a caller-supplied chain
  // deciding how much of that work happens.
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
    // See {@link HISTORIC_ISSUANCE}.
    historic: HISTORIC_ISSUANCE,
  })
  assertCapabilityToken(next)
  if (options?.verifyToken != null) {
    await options.verifyToken(next, head)
  }
  assertValidDelegation(next.payload, payload, atTime)
  await checkDelegationChain(next.payload, tail, { ...options, atTime })
}

/**
 * Check that `payload` authorises `permission`. `payload` is either an invocation (authority is
 * entirely the `cap` chain) or a capability presented directly (carries its own grant — a
 * `did:kokuin:` revoke event has no invocation to wrap it, so
 * `createControllerCapabilityVerifier` presents the capability itself). See {@link presentedGrant}.
 *
 * A presented capability's own claims bind like any link's: the request must be within *its* grant,
 * not merely its parent's, and its audience is subject to the deny set. Checking only its ancestors
 * made attenuation at the last hop a no-op and left the deny set blind to the actual holder.
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
    // This branch never reaches `checkDelegationChain`, so it needs its own audience check. Also the
    // shape `createControllerCapabilityVerifier` takes: an undelegated management capability minted by
    // the profile for its own device is exactly `iss === sub`.
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
    // A presented capability's own time claims are checked nowhere else: it never passes through
    // `verifyToken` here and the walk below starts at its parent, so without this an expired,
    // not-yet-valid or future-dated capability was accepted on this arm. Same three claims and `time`
    // as the `iss === sub` arm — the arms differ in how authority is derived, not when a token is valid.
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
  // Count `head` against the bound here, since this entry point peels it off before
  // `checkDelegationChain` applies the bound to the rest — without this, four admits five links, the
  // extra one free to an attacker controlling chain length. The bound inside `checkDelegationChain`
  // stays: a direct caller passes the whole chain, so there `capabilities.length` is the link count.
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
    // See {@link HISTORIC_ISSUANCE}.
    historic: HISTORIC_ISSUANCE,
  })
  assertCapabilityToken(capability)
  if (options?.verifyToken != null) {
    await options.verifyToken(capability, head)
  }

  // The presented capability's audience is the actual holder, and the one audience the walk never
  // reaches (`checkDelegationChain` starts at the parent). Without this a device the subject revoked
  // keeps invoking through one delegation level. After the parent verifies, and after the depth bound,
  // for the same reason as in `checkDelegationChain`: a deny set may fold a log.
  if (grant != null) {
    await assertAudienceNotRevoked(payload, options)
  }

  // Against its own grant when it has one: the parent must cover what the presented capability grants,
  // not merely this request. Both together are the attenuation rule (request within grant, grant
  // within parent); spreading `permission` over the payload collapsed them, dropping the last hop's
  // narrowing.
  const toCapability = (
    grant == null ? { ...payload, ...permission } : payload
  ) as CapabilityPayload
  assertValidDelegation(capability.payload, toCapability, time)
  await checkDelegationChain(capability.payload, tail, { ...options, atTime: time })
}

// Re-exported so catching the fail-closed throw needs nothing but this package: `@kokuin/token` is a
// plain dependency, not a peer, so a consumer would otherwise add a direct token dependency to name
// the error — the duplication that makes a cross-copy `instanceof` unreliable.
export {
  isUnresolvableIssuerError,
  UnresolvableIssuerError,
} from '@kokuin/token'

export type {
  CapabilityAuthorisation,
  ControllerCapabilityVerifier,
  ControllerCapabilityVerifierParams,
} from './controller.js'
export {
  assertRevokeCapabilityAudience,
  audienceConfirmation,
  createControllerCapabilityVerifier,
  REVOKE_AUDIENCE_KEY_MISMATCH,
  REVOKE_LIFETIME_TOO_LONG,
  REVOKE_NO_AUDIENCE_KEY,
  REVOKE_NO_POSITION,
  REVOKE_NOT_AUTHORISED,
  REVOKE_UNBOUNDED_LIFETIME,
} from './controller.js'
export type { RevocationBackend, RevocationOptions, RevocationRecord } from './revocation.js'
export {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
} from './revocation.js'
