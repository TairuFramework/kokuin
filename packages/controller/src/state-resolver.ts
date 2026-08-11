import {
  type DIDMethodResolver,
  IssuerKeyNotFoundError,
  type ResolvedAgreementKey,
  type ResolvedSigningKey,
  type ResolveIssuerHeader,
} from '@kokuin/token'

import { DID_PREFIX, decodeKey } from './events.js'
import type { KeyState } from './fold.js'

/** The method segment of {@link DID_PREFIX}, so the two cannot drift. */
export const DID_METHOD = DID_PREFIX.slice('did:'.length, -1)

/**
 * The key a token's `kid` names, or the head's first published key when it carries none.
 *
 * The format is `#<the multibase key exactly as it appears in `k`>` — a fragment whose body is the
 * key itself, matched against the folded key sets by membership. An index-based fragment was
 * rejected for this: an index means whatever the key set said at the time, and a token outlives
 * the state that gave its `kid` meaning.
 *
 * **Any key that was authoritative at some position within the current generation resolves**, not
 * only the head's. Answering from the head alone made a routine `rotate` invalidate every token,
 * capability and revocation record the profile had ever issued — including ones held by third
 * parties who cannot know a rotation happened. The spec reserves that blast radius for `reset`
 * ("discards everything under the prior generation, including every capability minted there") and
 * its remedy ladder — a cold rotate, with reset as the backstop — only means something if the two
 * differ. So a generation bump is the thing that invalidates, and the scan stops dead at the first
 * state from an earlier generation rather than continuing through it.
 *
 * Everything else stays as it was. A `kid` naming a key this profile never published, and one from
 * a superseded generation, are errors — never a fall back to `keys[0]`, which would check the
 * signature against a key the token never claimed. A `kid` absent still resolves to the head's
 * first key: accepting an earlier key when a token *names* it is not the same as volunteering one
 * when it names nothing, and `resolve` can only answer with one key.
 *
 * The bare key without the leading `#` is rejected rather than accepted as a second spelling: the
 * fragment form is wire-visible and effectively permanent, so it has exactly one spelling.
 *
 * Both rejections are an `IssuerKeyNotFoundError`, not the plain error the rest of this file
 * throws: the DID *was* resolved and its log *did* fold — what failed is the key the token named.
 * The distinction is load-bearing, not cosmetic. `resolveIssuerWithDoc` retypes everything else a
 * method resolver throws as `UnresolvableIssuerError`, and `@kokuin/capability`'s revocation
 * checker denies a capability on that type; since `kid` is an unauthenticated header field, a
 * fabricated record naming this DID and any invented key would otherwise deny every capability
 * this controller ever issued.
 */
function selectSigningKey(did: string, states: Array<KeyState>, kid?: string): string {
  const head = states[states.length - 1]
  if (kid == null) {
    return head.keys[0]
  }
  if (!kid.startsWith('#')) {
    throw new IssuerKeyNotFoundError(`Controller ${did} kid is not a key fragment: ${kid}`)
  }
  const key = kid.slice(1)
  // Backwards from the head, because the head's own key set is the overwhelmingly common answer.
  // `gen` never decreases across the fold, so the first state from another generation ends the
  // search — everything before it is superseded material, and reaching into it would undo the one
  // thing `reset` is for.
  for (let i = states.length - 1; i >= 0 && states[i].gen === head.gen; i--) {
    if (states[i].keys.includes(key)) {
      return key
    }
  }
  throw new IssuerKeyNotFoundError(
    `Controller ${did} kid names a key outside the current generation: ${kid}`,
  )
}

/** The signing key `header` names, out of an already-folded log. */
export function signingKeyFrom(
  did: string,
  states: Array<KeyState>,
  header: ResolveIssuerHeader,
): ResolvedSigningKey {
  if (states[states.length - 1].keys.length === 0) {
    throw new Error(`Controller ${did} has no signing key`)
  }
  const key = decodeKey(selectSigningKey(did, states, header.kid))
  if (key.alg === 'X25519') {
    throw new Error(`Controller ${did} signing key is not a signature algorithm: ${key.alg}`)
  }
  return { alg: key.alg, publicKey: key.publicKey }
}

/** The head's key agreement set, out of an already-folded log. */
export function agreementKeysFrom(
  did: string,
  states: Array<KeyState>,
): Array<ResolvedAgreementKey> {
  return states[states.length - 1].agreement.map((value) => {
    const key = decodeKey(value)
    if (key.alg !== 'X25519') {
      throw new Error(`Controller ${did} publishes an unsupported agreement key: ${key.alg}`)
    }
    return { alg: key.alg, publicKey: key.publicKey }
  })
}

/**
 * A `DIDMethodResolver` answering for exactly one profile, out of state that is already folded.
 *
 * The fold hands one of these to a capability-authorised revoke's verifier, built from the states
 * *before* the event being verified. That is what makes the prefix contract unforgettable: the
 * verifier no longer needs a registry that knows which position it is at, because the only party
 * that knows — the fold — supplies the answer. See `FoldOptions.verifyCapability`.
 *
 * Answers only for `did`. Any other identifier is an `Unknown DID`, so a caller merging this into
 * a wider registry can fall back to its own resolver for a delegate that happens to be another
 * `did:kokuin:` profile, and can never accidentally serve one profile's key state for another's.
 *
 * Not a cache and not a snapshot of a live log: the states are the caller's, fixed at construction.
 */
export function createStateResolver(did: string, states: Array<KeyState>): DIDMethodResolver {
  function statesFor(asked: string): Array<KeyState> {
    if (asked !== did) {
      throw new Error(`Unknown DID: ${asked}`)
    }
    return states
  }
  return {
    method: DID_METHOD,
    async resolve(asked: string, header: ResolveIssuerHeader = {}): Promise<ResolvedSigningKey> {
      return signingKeyFrom(asked, statesFor(asked), header)
    },
    async resolveDenySet(asked: string): Promise<ReadonlySet<string>> {
      const known = statesFor(asked)
      return known[known.length - 1].deny
    },
    async resolveAgreementKey(asked: string): Promise<Array<ResolvedAgreementKey>> {
      return agreementKeysFrom(asked, statesFor(asked))
    },
  }
}
