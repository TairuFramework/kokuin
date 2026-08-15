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
 * The `kid` fragment's body, or `null` when the header names no key. Format is `#<the multibase key
 * exactly as it appears in `k`>`, matched against the folded key sets by membership — an index-based
 * fragment would mean whatever the key set said at the time, and a token outlives that. The bare key
 * without `#` is rejected, not accepted as a second spelling.
 *
 * Every rejection on this path is an `IssuerKeyNotFoundError`, not the plain error the rest of this
 * file throws: the DID resolved and its log folded — what failed is the key. Load-bearing, because
 * `resolveIssuerWithDoc` retypes everything else as `UnresolvableIssuerError`, on which
 * `@kokuin/capability` *denies* a capability; since `kid` is unauthenticated, a fabricated record
 * naming this DID and any invented key would otherwise deny every capability this controller issued.
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
 * The key a token's `kid` names, out of the **head's** key set alone — what `resolve` answers, and
 * the only question authenticating a live signer may ask ("can this profile sign with this key
 * *now*"). A key the profile rotated away is not an answer, which is what makes a `rotate` retire a
 * leaked authority key for new issuance — the middle rung of the `revoke → rotate → reset` ladder.
 *
 * A `kid` naming a key not in the head's `k` (including one published earlier) is an error, **never
 * a fall back to `keys[0]`**, which would check the signature against a key the token never claimed.
 * An absent `kid` resolves to the head's first key: volunteering one is not the same as accepting one
 * the token names. Past-issued material is {@link historicSigningKey}, via explicit `resolveHistoric`.
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
 * `resolveHistoric` answers. It accepts a key the profile has since rotated away, so it establishes
 * "this profile did once hold this key", never "holds". The right answer for material minted in the
 * past (an already-issued capability, a revocation record), because a routine `rotate` must not
 * invalidate what the profile issued to third parties who cannot know it rotated; the wrong answer
 * for a live signer.
 *
 * A `reset` is what invalidates (it discards everything under the prior generation), and `gen` never
 * decreases, so the backwards scan stops dead at the first earlier-generation state. Runs backwards
 * because the head's own key set is the common answer. A `kid` naming a never-published key, or one
 * from a superseded generation, is an error — never a fall back to `keys[0]`.
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
 * What a token signed by a revoked key is rejected with. The `#`-prefixed key follows after `: `, so
 * match with `startsWith`.
 */
export const KEY_REVOKED = 'kid names a key the controller has revoked'

/**
 * The signing key `header` names, out of an already-folded log. `historic` picks which question above
 * is asked, and defaults to the safe one.
 *
 * **A revoked key answers neither question.** A `rev` naming `#<key>` retires a key for material it
 * has *already* signed, and this is where that bites — every `did:kokuin:` signature check reaches a
 * resolved key through here, so the denial covers `verifyToken` on both `historic` settings, every
 * capability and revocation record `@kokuin/capability` verifies, and the fold's own cap-authorised
 * revoke. The historic arm is the live one: a revoked key is never in the head's `k` (the
 * `KeyState.deny` invariant), so only the backwards scan can select one, and without this
 * `resolveHistoric` would accept a leaked key forever.
 *
 * The head arm cannot be reached from a log this package folded, but is not decoration: `states`
 * arrives from the caller, and the invariant is the fold's property, not the array's — a
 * caller-built state whose head publishes a key it also denies resolves to nothing here.
 *
 * **Evaluated against the head's deny set, never the position the key was selected at.** A denial is
 * about the key, not one event, and the position an artefact carries is author-supplied — else a
 * thief presents a token resolving at a position before the revoke. Deliberately *not* how a DID
 * denial behaves inside the fold, where `states[i]` is consulted at position `i` because "was this
 * author allowed to act *here*" is the whole question; the two rules answer different questions.
 * Inside the fold they coincide anyway: `createStateResolver` gets the prefix `states[0..i-1]`, so
 * its head *is* the position being verified.
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
  // `IssuerKeyNotFoundError` like every rejection here: the DID resolved and the log folded, and what
  // failed is the key. Retyping it unresolvable would let a `kid` (unauthenticated) make this
  // controller read as unresolvable to every fail-closed caller. See {@link keyFromKid}.
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
 * The head's key agreement set, minus anything it has revoked. A `rev` may name an agreement key as
 * readily as a signing one (the target spelling is the key, not its purpose), and these are the keys
 * a *sender* encrypts to — encrypting to a revoked key is the one outcome a denial must prevent.
 *
 * Like the signing side, unreachable from a log this package folded (the `KeyState.deny` invariant)
 * but `states` arrives from the caller. Filtering to empty is the honest answer for a state that
 * denies everything it publishes: `@kokuin/jwe` then encrypts nothing, the fail-closed direction.
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
 * A `DIDMethodResolver` answering for exactly one profile, out of already-folded state. The fold
 * hands one to a capability-authorised revoke's verifier, built from the states *before* the event
 * being verified — the prefix contract made unforgettable: the verifier no longer needs a
 * position-aware registry, because the fold supplies the answer. See `FoldOptions.verifyCapability`.
 *
 * Answers only for `did`; any other identifier is `Unknown DID`, so a caller merging this into a
 * wider registry falls back to its own resolver for another `did:kokuin:` delegate and never serves
 * one profile's state for another's. Not a cache: the states are the caller's, fixed at construction.
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
    // The head of *this prefix*, not the log: these states end at the position the fold is verifying.
    // A capability issued before that position is the archived material `resolveHistoric` exists for.
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
