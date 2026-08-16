import {
  findMethodResolver,
  normalizeDID,
  type SignedHeader,
  type SignedPayload,
  type SigningIdentity,
  verifyToken,
} from '@kokuin/token'

import { assertValidPattern, hasPermission, isStringOrStringArray } from './patterns.js'
import { assertNonExpired, assertValidIssuedAt, assertValidNotBefore, now } from './time.js'
import { assertCapabilityToken } from './token.js'
import type {
  CapabilityPayload,
  CapabilityToken,
  CreateCapabilityOptions,
  DelegationChainOptions,
  Permission,
  SignCapabilityPayload,
} from './types.js'

/**
 * Maximum delegation links an offline verifier will walk.
 *
 * Four: management → device → connector is three, plus one of headroom. Lowered from 20 —
 * lowering the default can only reject chains, never accept new ones, and `maxDepth` stays
 * overridable per call for anything that legitimately needs more.
 */
export const DEFAULT_MAX_DELEGATION_DEPTH = 4

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
