import { findMethodResolver, normalizeDID } from '@kokuin/token'

import type { DelegationChainOptions } from './types.js'

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
 * two target types cannot collide. DID entries compare canonically.
 */
export async function assertAudienceNotRevoked(
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
  // Third-party resolvers may return raw entries, so canonicalise both sides.
  const canonicalDenied = new Set([...denied].map(normalizeDID))
  if (canonicalDenied.has(normalizeDID(aud))) {
    throw new Error(`${AUDIENCE_REVOKED}: ${aud}`)
  }
}
