import {
  normalizeDID,
  type SignedHeader,
  type SignedPayload,
  type SigningIdentity,
  verifyToken,
} from '@kokuin/token'

import { assertAudienceNotRevoked } from './audience.js'
import { assertMemberRoot, isMemberClaim } from './member.js'
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

export type CreateCapabilityParams<Payload extends SignCapabilityPayload = SignCapabilityPayload> =
  {
    signer: SigningIdentity
    payload: Payload
    header?: Record<string, unknown>
  } & CreateCapabilityOptions

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

function captureOptions<Options extends CreateCapabilityOptions | DelegationChainOptions>(
  options?: Options,
): Options | undefined {
  return options == null ? undefined : { ...options, verifiers: { ...options.verifiers } }
}

function assertExpiryWithinParent(parent: { exp?: number }, child: { exp?: number }): void {
  if (parent.exp != null && (child.exp == null || child.exp > parent.exp)) {
    throw new Error('Invalid capability: child expiry exceeds parent capability')
  }
}

export async function createCapability<
  Payload extends SignCapabilityPayload = SignCapabilityPayload,
>({
  signer,
  payload,
  header,
  ...options
}: CreateCapabilityParams<Payload>): Promise<
  CapabilityToken<Payload & { iss: string }, SignedHeader>
> {
  const capturedOptions = captureOptions(options)
  const signerID = signer.id

  // Validate act/res patterns
  assertValidPattern(payload.act)
  assertValidPattern(payload.res)

  // If signer is the subject, no parent validation needed (root capability)
  if (normalizeDID(payload.sub) === normalizeDID(signerID)) {
    return await signer.signToken({ payload, header })
  }

  // A management member minting on the subject's behalf: also a chain root, its authority the
  // signer's membership rather than a parent. Not checked against the log here — this package holds
  // no view of it, and the verifier asks anyway. What is checked is the shape a verifier bounds the
  // grant by: a well-formed claim, both `exp` and `iat`, and `exp` not before `iat`. The lifetime and
  // lease bounds are left to the verifier: the maximum lifetime is the verifier's setting, and a
  // mint-side default would refuse grants a verifier configured wider accepts.
  if (capturedOptions?.member != null) {
    const { member } = capturedOptions
    if (!isMemberClaim(member)) {
      throw new Error('Invalid capability: malformed mbr claim')
    }
    if (typeof payload.exp !== 'number' || typeof payload.iat !== 'number') {
      throw new Error('Invalid capability: a member grant requires exp and iat')
    }
    if (payload.exp < payload.iat) {
      throw new Error('Invalid capability: a member grant expires before it is issued')
    }
    return await signer.signToken({
      payload: { ...payload, mbr: { add: member.add, g: member.g } },
      header,
    })
  }

  if (capturedOptions?.parentCapability == null) {
    throw new Error(
      'Invalid capability: parentCapability required when delegating for another subject',
    )
  }

  const parent = await verifyToken<CapabilityPayload>({
    token: capturedOptions.parentCapability,
    crypto: capturedOptions.crypto,
    cache: capturedOptions.cache,
    resolver: capturedOptions.resolver,
    methods: capturedOptions.methods,
    verifiers: capturedOptions.verifiers,
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

  assertNonExpired({ payload: parent.payload })
  assertExpiryWithinParent(parent.payload, payload)

  const newPermission: Permission = {
    act: payload.act,
    res: payload.res,
  }
  const parentPermission: Permission = {
    act: parent.payload.act,
    res: parent.payload.res,
  }

  if (!hasPermission({ expected: newPermission, granted: parentPermission })) {
    throw new Error('Invalid capability: delegated permission exceeds parent capability')
  }

  return await signer.signToken({ payload, header })
}

export type AssertValidDelegationParams = {
  from: CapabilityPayload
  to: CapabilityPayload
  atTime?: number
}

export function assertValidDelegation({ atTime, to, from }: AssertValidDelegationParams): void {
  const time = atTime ?? now()
  if (normalizeDID(to.iss) !== normalizeDID(from.aud)) {
    throw new Error('Invalid capability: audience mismatch')
  }
  if (normalizeDID(to.sub) !== normalizeDID(from.sub)) {
    throw new Error('Invalid capability: subject mismatch')
  }
  assertNonExpired({ payload: from, atTime: time })
  assertValidIssuedAt({ payload: from, atTime: time })
  if (!hasPermission({ expected: to, granted: from })) {
    throw new Error('Invalid capability: permission mismatch')
  }
}

/**
 * The grant a `checkCapability` payload makes on its own behalf, or `undefined` when it makes none.
 * The payload is either an **invocation** (no permission of its own; its authority is the `cap`
 * chain) or a **capability presented directly** (carries its minted grant, with no invocation to
 * wrap it — a member-issued grant checked on its own, or any capability a caller verified itself). Only
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

export type CheckDelegationChainParams = {
  payload: CapabilityPayload
  capabilities: Array<string>
} & DelegationChainOptions

export async function checkDelegationChain({
  capabilities,
  payload,
  ...inputOptions
}: CheckDelegationChainParams): Promise<void> {
  const options = captureOptions(inputOptions)
  const maxDepth = options?.maxDepth ?? DEFAULT_MAX_DELEGATION_DEPTH
  const atTime = options?.atTime ?? now()

  if (capabilities.length > maxDepth) {
    throw new Error(`Invalid capability: delegation chain exceeds maximum depth of ${maxDepth}`)
  }

  // Every link passes through here as `payload`, so the audience checks below cover the whole chain
  // above the payload `checkCapability` was handed — a revoked *intermediate* is what a per-leaf
  // check misses. After the depth bound, not before: this may fold a log, and the bound stops a
  // caller-supplied chain deciding how much of that work happens.

  if (capabilities.length === 0) {
    if (normalizeDID(payload.iss) !== normalizeDID(payload.sub)) {
      if (payload.mbr == null) {
        throw new Error('Invalid capability: issuer should be subject')
      }
      // Issued by a management member of the subject. Its audience check is part of the arm, asked
      // of the same view as the issuer's membership. `assertMemberRoot` requires the link's signature
      // to have verified: the walk did so before recursing here, and a direct caller with an empty
      // chain vouches for its payload, as on the subject arm.
      await assertMemberRoot({ ...options, payload, time: atTime })
      return
    }
    await assertAudienceNotRevoked(payload, options)
    assertNonExpired({ payload, atTime })
    assertValidNotBefore({ payload: payload as { nbf?: number }, atTime })
    assertValidIssuedAt({ payload, atTime })
    return
  }

  await assertAudienceNotRevoked(payload, options)

  const [head, ...tail] = capabilities
  if (head === undefined) {
    throw new Error('Invalid capability: empty delegation chain')
  }
  // Verify the leaf capability's own time claims (exp/nbf) at the same reference
  // time used for the delegation checks, so a capability that was valid when the
  // request was issued is not rejected by a later wall-clock during verification.
  const next = await verifyToken<CapabilityPayload>({
    token: head,
    atTime,
    crypto: options?.crypto,
    cache: options?.cache,
    resolver: options?.resolver,
    methods: options?.methods,
    verifiers: options?.verifiers,
    // See {@link HISTORIC_ISSUANCE}.
    historic: HISTORIC_ISSUANCE,
  })
  assertCapabilityToken(next)
  if (options?.verifyToken != null) {
    await options.verifyToken({ token: next, raw: head })
  }
  assertValidDelegation({ from: next.payload, to: payload, atTime })
  assertExpiryWithinParent(next.payload, payload)
  await checkDelegationChain({
    ...options,
    payload: next.payload,
    capabilities: tail,
    atTime,
  })
}

/**
 * Check that `payload` authorises `permission`. `payload` is either an invocation (authority is
 * entirely the `cap` chain) or a capability presented directly (carries its own grant, with no
 * invocation to wrap it). See {@link presentedGrant}.
 *
 * A presented capability's own claims bind like any link's: the request must be within *its* grant,
 * not merely its parent's, and its audience is subject to the deny set. Checking only its ancestors
 * made attenuation at the last hop a no-op and left the deny set blind to the actual holder.
 */
export type CheckCapabilityParams = {
  permission: Permission
  payload: SignedPayload
} & DelegationChainOptions

export async function checkCapability({
  payload,
  permission,
  ...inputOptions
}: CheckCapabilityParams): Promise<void> {
  const options = captureOptions(inputOptions)
  if (payload.sub == null) {
    throw new Error('Invalid payload: no subject')
  }

  const time = options?.atTime ?? now()
  if (normalizeDID(payload.iss) === normalizeDID(payload.sub)) {
    // Subject is issuer, no delegation required
    // But still need to validate the permission is granted
    assertNonExpired({ payload, atTime: time })
    assertValidNotBefore({ payload: payload as { nbf?: number }, atTime: time })
    assertValidIssuedAt({ payload: payload as { iat?: number }, atTime: time })
    // This branch never reaches `checkDelegationChain`, so it needs its own audience check.
    await assertAudienceNotRevoked(payload, options)

    // Validate that the token grants the requested permission
    const p = payload as Record<string, unknown>
    const act = p.act as string | Array<string> | undefined
    const res = p.res as string | Array<string> | undefined

    if (act == null || res == null) {
      throw new Error('Invalid payload: missing act or res for self-issued token')
    }

    if (!hasPermission({ expected: permission, granted: { act, res } })) {
      throw new Error('Invalid capability: permission not granted')
    }

    return
  }

  // A grant issued by a management member, presented directly: the other root arm. As in the
  // `iss === sub` arm, the caller verified the token's signature; the request must be within the
  // grant, and everything else is the membership check, audience included.
  if (payload.cap == null && (payload as { mbr?: unknown }).mbr != null) {
    const grant = presentedGrant(payload)
    if (grant == null) {
      throw new Error('Invalid payload: missing act or res for member-issued token')
    }
    if (!hasPermission({ expected: permission, granted: grant })) {
      throw new Error('Invalid capability: permission not granted')
    }
    await assertMemberRoot({ ...options, payload: payload as CapabilityPayload, time })
    return
  }

  // The grant the payload makes on its own behalf, when it makes one. Checked before anything is
  // resolved or verified: it costs nothing, and a request outside the presented grant is refused
  // whatever its ancestors say.
  const grant = presentedGrant(payload)
  if (grant != null) {
    if (!hasPermission({ expected: permission, granted: grant })) {
      throw new Error('Invalid capability: permission not granted')
    }
    // A presented capability's own time claims are checked nowhere else: it never passes through
    // `verifyToken` here and the walk below starts at its parent, so without this an expired,
    // not-yet-valid or future-dated capability was accepted on this arm. Same three claims and `time`
    // as the `iss === sub` arm — the arms differ in how authority is derived, not when a token is valid.
    assertNonExpired({ payload, atTime: time })
    assertValidNotBefore({ payload: payload as { nbf?: number }, atTime: time })
    assertValidIssuedAt({ payload: payload as { iat?: number }, atTime: time })
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
  const capability = await verifyToken<CapabilityPayload>({
    token: head,
    atTime: time,
    crypto: options?.crypto,
    cache: options?.cache,
    resolver: options?.resolver,
    methods: options?.methods,
    verifiers: options?.verifiers,
    // See {@link HISTORIC_ISSUANCE}.
    historic: HISTORIC_ISSUANCE,
  })
  assertCapabilityToken(capability)
  if (options?.verifyToken != null) {
    await options.verifyToken({ token: capability, raw: head })
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
  assertValidDelegation({ from: capability.payload, to: toCapability, atTime: time })
  if (grant != null) {
    assertExpiryWithinParent(capability.payload, toCapability)
  }
  await checkDelegationChain({
    ...options,
    payload: capability.payload,
    capabilities: tail,
    atTime: time,
  })
}
