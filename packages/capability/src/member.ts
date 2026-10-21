import {
  findMethodResolver,
  type ResolvedMember,
  type ResolvedSigningKey,
  signingKeysOf,
} from '@kokuin/token'

import { assertAudienceNotRevoked } from './audience.js'
import { assertNonExpired, assertValidIssuedAt, assertValidNotBefore } from './time.js'
import type { CapabilityPayload, DelegationChainOptions, MemberClaim } from './types.js'

/**
 * Default longest `exp - iat` of a grant issued by a management member: 12 hours. The window an
 * offline verifier may keep accepting an edge holder the subject has since revoked, since it learns
 * of the revocation only with a newer log. Configurable per verification through
 * `DelegationChainOptions.maxMemberGrantLifetime`.
 */
export const DEFAULT_MEMBER_GRANT_LIFETIME = 43_200

/** The subject's method cannot say who its members are, so no member-issued grant can verify. */
export const MEMBER_GRANT_NO_RESOLVER =
  "Invalid capability: the subject's method cannot resolve management members"

/** The issuer is not an effective member of the subject under the `mbr` claim it names. */
export const MEMBER_GRANT_NOT_MEMBER =
  'Invalid capability: issuer is not an effective management member of the subject'

/** The issuer DID does not carry exactly the key the subject's log pins for the member. */
export const MEMBER_GRANT_KEY_MISMATCH =
  'Invalid capability: issuer does not carry exactly the key the subject pins for the member'

/** The grant has no `exp`, or outlives the issuer's lease. */
export const MEMBER_GRANT_PAST_LEASE =
  "Invalid capability: member grant expires after the issuer's lease"

/** The grant's `exp - iat` exceeds the verifier's maximum. */
export const MEMBER_GRANT_TOO_LONG = 'Invalid capability: member grant lifetime exceeds the maximum'

/** The grant has no `iat`, so its lifetime cannot be bounded. */
export const MEMBER_GRANT_NO_IAT = 'Invalid capability: member grant has no iat'

export function isMemberClaim(value: unknown): value is MemberClaim {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  // Exactly these two members: the claim names an incarnation and nothing else, so an extension
  // fails closed rather than riding along unread.
  if (Object.keys(value).length !== 2) {
    return false
  }
  const { add, g } = value as Record<string, unknown>
  return typeof add === 'string' && add !== '' && Number.isSafeInteger(g) && (g as number) >= 0
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

/**
 * Whether `iss` carries exactly `pinned` as its signing key: one key, Ed25519, byte-equal. Total:
 * an identifier that claims to carry a key and does not (`signingKeysOf` throws, a `did:peer:4` long
 * form whose document does not hash to its prefix among them) is no match.
 */
function carriesExactly(iss: string, pinned: ResolvedSigningKey): boolean {
  let keys: Array<ResolvedSigningKey> | null
  try {
    keys = signingKeysOf(iss)
  } catch {
    return false
  }
  if (keys == null || keys.length !== 1) {
    return false
  }
  const [key] = keys
  return (
    key != null &&
    key.alg === 'EdDSA' &&
    pinned.alg === 'EdDSA' &&
    bytesEqual(key.publicKey, pinned.publicKey)
  )
}

/**
 * Accept `payload` as a chain root issued by a **management member** of its subject rather than by
 * the subject itself — the arm next to `iss === sub` in `checkCapability` and the delegation walk.
 * Same power as a root grant. It cannot confer management power: membership comes only from a root
 * add in the subject's log, never from a capability, so a holder of a member grant copying its `mbr`
 * onto a root of its own is simply not a member.
 *
 * **Precondition: `payload` is the payload of a token whose signature verified against `iss`** —
 * the walk verifies each link before this runs, and a caller presenting a grant directly to
 * `checkCapability` must have verified it, as for the `iss === sub` arm. Membership is asked only
 * after that. The order matters because the log's member question compares DIDs canonically, which
 * for a `did:peer:4` reads only the short prefix: a long form sharing a member's prefix but
 * embedding another document gets the real member's pin back. The key check below closes that, and
 * it is what binds the verified signature to the pin: the issuer DID must carry **exactly** the
 * pinned key, so the key the signature verified against can be no other (a forged long form's
 * document does not hash to its prefix, so it carries nothing at all).
 *
 * Checked in order: `mbr` well-formed; the subject's method can resolve members; the issuer is an
 * effective member under that incarnation and the head's generation; it carries exactly the pinned
 * key; `exp` is within the issuer's lease; `iat` is present and `exp - iat` within
 * `maxMemberGrantLifetime`; the time claims; the audience not denied.
 *
 * **Pass one frozen view.** Membership, pin, lease and every audience denial on the chain must come
 * from one state of the subject's log, or a revoke landing between two of the questions gives a
 * verdict no single state supports. With `@kokuin/controller`, put `resolver.frozen()` in `methods`
 * for each verification, not the live resolver.
 */
export async function assertMemberRoot(
  payload: CapabilityPayload,
  options: DelegationChainOptions | undefined,
  time: number,
): Promise<void> {
  const { iss, sub, mbr } = payload
  if (!isMemberClaim(mbr)) {
    throw new Error(`${MEMBER_GRANT_NOT_MEMBER}: malformed mbr claim`)
  }

  const resolveMember =
    options?.methods == null ? undefined : findMethodResolver(options.methods, sub)?.resolveMember
  if (resolveMember == null) {
    throw new Error(`${MEMBER_GRANT_NO_RESOLVER}: ${sub}`)
  }

  // Any refusal — unknown, removed or denied incarnation, another generation, an unresolvable or
  // saturated log — reads alike: the issuer is not a member this verifier can stand behind.
  let member: ResolvedMember
  try {
    member = await resolveMember(sub, { did: iss, add: mbr.add, gen: mbr.g })
  } catch (cause) {
    throw new Error(`${MEMBER_GRANT_NOT_MEMBER}: ${iss}`, { cause })
  }

  if (!carriesExactly(iss, member.key)) {
    throw new Error(`${MEMBER_GRANT_KEY_MISMATCH}: ${iss}`)
  }

  // Bounded at mint: the lease and the lifetime are judged against the grant's own claims, so a
  // grant that would outlive either is refused outright rather than trimmed.
  const { exp, iat } = payload
  if (typeof exp !== 'number' || !(exp <= member.lease)) {
    throw new Error(`${MEMBER_GRANT_PAST_LEASE}: ${member.lease}`)
  }
  if (typeof iat !== 'number') {
    throw new Error(MEMBER_GRANT_NO_IAT)
  }
  const maxLifetime = options?.maxMemberGrantLifetime ?? DEFAULT_MEMBER_GRANT_LIFETIME
  if (!(exp - iat <= maxLifetime)) {
    throw new Error(`${MEMBER_GRANT_TOO_LONG}: ${maxLifetime}s`)
  }

  assertNonExpired(payload, time)
  assertValidNotBefore(payload as { nbf?: number }, time)
  assertValidIssuedAt(payload, time)
  await assertAudienceNotRevoked(payload, options)
}
