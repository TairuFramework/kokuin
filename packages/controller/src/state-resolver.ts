import {
  type DIDMethodResolver,
  IssuerKeyNotFoundError,
  type ResolvedAgreementKey,
  type ResolvedSigningKey,
  type ResolveIssuerHeader,
} from '@kokuin/token'

import { DID_PREFIX, decodeKey, keyTarget } from './events.js'
import type { KeyState } from './fold.js'

/** The method segment of {@link DID_PREFIX}, so the two cannot drift. */
export const DID_METHOD = DID_PREFIX.slice('did:'.length, -1)

/**
 * The `kid` fragment's body, or `null` when the header names no key.
 *
 * The format is `#<the multibase key exactly as it appears in `k`>` — a fragment whose body is the
 * key itself, matched against the folded key sets by membership. An index-based fragment was
 * rejected for this: an index means whatever the key set said at the time, and a token outlives
 * the state that gave its `kid` meaning.
 *
 * The bare key without the leading `#` is rejected rather than accepted as a second spelling: the
 * fragment form is wire-visible and effectively permanent, so it has exactly one spelling.
 *
 * Every rejection on this path — here and in both selectors below — is an `IssuerKeyNotFoundError`,
 * not the plain error the rest of this file throws: the DID *was* resolved and its log *did* fold —
 * what failed is the key the token named. The distinction is load-bearing, not cosmetic.
 * `resolveIssuerWithDoc` retypes everything else a method resolver throws as
 * `UnresolvableIssuerError`, and `@kokuin/capability`'s revocation checker denies a capability on
 * that type; since `kid` is an unauthenticated header field, a fabricated record naming this DID
 * and any invented key would otherwise deny every capability this controller ever issued.
 */
function keyFromKid(did: string, kid: string | undefined): string | null {
  if (kid == null) {
    return null
  }
  if (!kid.startsWith('#')) {
    throw new IssuerKeyNotFoundError(`Controller ${did} kid is not a key fragment: ${kid}`)
  }
  return kid.slice(1)
}

/**
 * The key a token's `kid` names, out of the **head's** key set alone — what `resolve` answers.
 *
 * This is the question "can this profile sign with this key *now*", and it is the only one that
 * authenticating a live signer may ask. A key the profile has rotated away is not an answer to it,
 * whatever the reason for the rotation was — and the reason that matters is compromise: with the
 * head-only rule, a `rotate` actually retires a leaked authority key for new issuance, which is
 * what makes the middle rung of the `revoke → rotate → reset` remedy ladder mean anything. Before
 * the split this scanned the whole generation, so a thief holding a rotated-away key went on
 * minting fresh, fully verifying tokens until the profile reset.
 *
 * A `kid` naming a key that is not in the head's `k` — including one this profile published
 * earlier — is an error, never a fall back to `keys[0]`, which would check the signature against a
 * key the token never claimed. A `kid` absent resolves to the head's first key: volunteering one
 * when the token names nothing is not the same as accepting one it names, and `resolve` can only
 * answer with a single key.
 *
 * Verifying material the profile issued *in the past* is {@link historicSigningKey}, reached only
 * by an explicit `resolveHistoric`.
 */
function headSigningKey(did: string, states: Array<KeyState>, kid?: string): string {
  const head = states[states.length - 1]
  const key = keyFromKid(did, kid)
  if (key == null) {
    return head.keys[0]
  }
  if (!head.keys.includes(key)) {
    throw new IssuerKeyNotFoundError(
      `Controller ${did} kid names a key that is not current: ${kid}`,
    )
  }
  return key
}

/**
 * The key a token's `kid` names, out of **every position in the current generation** — what
 * `resolveHistoric` answers.
 *
 * A different question from {@link headSigningKey}, and the caller has to have said which one it
 * is asking. This one accepts a key the profile has since rotated away, so what it establishes is
 * "this profile did once hold this key", never "this profile holds this key". That is the right
 * answer for an artefact minted in the past — an already-issued capability, a revocation record, an
 * archived grant — because a routine `rotate` must not invalidate material the profile has already
 * issued to third parties who cannot know a rotation happened. It is the wrong answer for anything
 * that authenticates a live signer, where a stolen-and-rotated-away key would still pass.
 *
 * A `reset` is what invalidates: the spec reserves that blast radius for it ("discards everything
 * under the prior generation, including every capability minted there"). `gen` never decreases
 * across the fold, so the scan stops dead at the first state from an earlier generation rather than
 * continuing through it.
 *
 * The scan runs backwards from the head, because the head's own key set is the overwhelmingly
 * common answer. A `kid` naming a key this profile never published, and one from a superseded
 * generation, are errors — never a fall back to `keys[0]`, for the same reason as above.
 */
function historicSigningKey(did: string, states: Array<KeyState>, kid?: string): string {
  const head = states[states.length - 1]
  const key = keyFromKid(did, kid)
  if (key == null) {
    return head.keys[0]
  }
  for (let i = states.length - 1; i >= 0 && states[i].gen === head.gen; i--) {
    if (states[i].keys.includes(key)) {
      return key
    }
  }
  throw new IssuerKeyNotFoundError(
    `Controller ${did} kid names a key outside the current generation: ${kid}`,
  )
}

/**
 * What a token signed by a key the profile has revoked is rejected with. The `#`-prefixed key
 * follows after `: `, so match with `startsWith`.
 */
export const KEY_REVOKED = 'kid names a key the controller has revoked'

/**
 * The signing key `header` names, out of an already-folded log.
 *
 * `historic` picks which of the two questions above is being asked, and defaults to the safe one.
 * See {@link headSigningKey} and {@link historicSigningKey}.
 *
 * **A revoked key answers neither question.** A `rev` naming `#<key>` (see `RevokeEvent.x`) is what
 * retires a key for material it has *already* signed, and this is where that bites — every
 * `did:kokuin:` signature check in this stack reaches a resolved key through this function, so
 * making the denial bite here covers `verifyToken` on both settings of `historic`, every capability
 * and revocation record `@kokuin/capability` verifies, and the fold's own capability-authorised
 * revoke, which resolves through `createStateResolver` below.
 *
 * The historic arm is the one the feature exists for, and the one that is live in ordinary use: a
 * revoked key is never in the head's `k` — that is the invariant on `KeyState.deny` — so only the
 * backwards scan can select one. Without this check, `resolveHistoric` would go on accepting a
 * leaked key forever, because surviving a rotate is precisely what it promises; a `rotate` retires
 * a key for new issuance and can retire it for nothing else.
 *
 * The head arm cannot be reached from a log this package folded, and is not therefore decoration:
 * `createStateResolver` is handed a `states` array by its caller, and the invariant is the fold's
 * property, not the array's. A caller-built or third-party-folded state whose head publishes a key
 * it also denies resolves to nothing here rather than to the key.
 *
 * **Evaluated against the head's deny set, never against the position the key was selected at.** A
 * denial is a statement about the key, not about one event, and the position an artefact carries is
 * author-supplied — a thief would otherwise present a token whose `kid` resolves at a position
 * before the revoke and be answered from there. This is the same reasoning
 * `assertAudienceNotRevoked` documents for `aud`, and it is deliberately *not* how a DID denial
 * behaves inside the fold: there `states[i]` is consulted at position `i`, because the position
 * being verified is the whole question — an event is authored at one place in the log, and a later
 * clearing must not retroactively validate it. Both rules coexist because they answer different
 * questions: "was this author allowed to act here" versus "is this key usable now".
 *
 * Inside the fold the two coincide anyway: `createStateResolver` is handed the prefix
 * `states[0..i-1]`, so its head *is* the position being verified.
 */
export function signingKeyFrom(
  did: string,
  states: Array<KeyState>,
  header: ResolveIssuerHeader,
  historic = false,
): ResolvedSigningKey {
  const head = states[states.length - 1]
  if (head.keys.length === 0) {
    throw new Error(`Controller ${did} has no signing key`)
  }
  const selected = historic
    ? historicSigningKey(did, states, header.kid)
    : headSigningKey(did, states, header.kid)
  // An `IssuerKeyNotFoundError` like every other rejection on this path, and for the same reason:
  // the DID resolved and its log folded, and what failed is the key. Retyping it as unresolvable
  // would let a `kid` — an unauthenticated header field — make this controller read as unresolvable
  // to every fail-closed caller. See {@link keyFromKid}.
  if (head.deny.has(keyTarget(selected))) {
    throw new IssuerKeyNotFoundError(`Controller ${did} ${KEY_REVOKED}: ${keyTarget(selected)}`)
  }
  const key = decodeKey(selected)
  if (key.alg === 'X25519') {
    throw new Error(`Controller ${did} signing key is not a signature algorithm: ${key.alg}`)
  }
  return { alg: key.alg, publicKey: key.publicKey }
}

/**
 * The head's key agreement set, out of an already-folded log, minus anything it has revoked.
 *
 * A `rev` may name an agreement key as readily as a signing one — the target spelling is the key,
 * not the key's purpose — so leaving this unfiltered would make exactly that denial inert while
 * every other one bit. These are the keys a *sender* encrypts to, and encrypting to a key the
 * recipient has revoked is the one outcome a denial must prevent.
 *
 * Like the signing side, this cannot be reached from a log this package folded — see the invariant
 * on `KeyState.deny` — and, like it, `states` arrives from the caller. Filtering the set to empty is
 * the honest answer for a state that denies everything it publishes; `@kokuin/jwe` reports "no
 * supported key agreement algorithm" and encrypts nothing, which is the fail-closed direction.
 */
export function agreementKeysFrom(
  did: string,
  states: Array<KeyState>,
): Array<ResolvedAgreementKey> {
  const head = states[states.length - 1]
  return head.agreement.flatMap((value) => {
    if (head.deny.has(keyTarget(value))) {
      return []
    }
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
    // The head of *this prefix*, not of the log: these states end at the position the fold is
    // verifying. A capability the profile issued before that position is exactly the archived
    // material `resolveHistoric` exists for — it must survive a rotate the profile made in between
    // — so a fold verifying one asks this member. See `signingKeyFrom`.
    async resolveHistoric(
      asked: string,
      header: ResolveIssuerHeader = {},
    ): Promise<ResolvedSigningKey> {
      return signingKeyFrom(asked, statesFor(asked), header, true)
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
