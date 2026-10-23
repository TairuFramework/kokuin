import {
  type DIDMethodResolver,
  IssuerKeyNotFoundError,
  type MemberQuery,
  normalizeDID,
  type ResolvedAgreementKey,
  type ResolvedMember,
  type ResolvedSigningKey,
  type ResolveIssuerHeader,
} from '@kokuin/token'

import { DID_PREFIX, keyTarget } from './events.js'
import type { KeyState } from './fold.js'
import { decodeKey } from './keys.js'
import { denialTargetsMember } from './members.js'

/** The method segment of {@link DID_PREFIX}, so the two cannot drift. */
export const DID_METHOD = DID_PREFIX.slice('did:'.length, -1)

/**
 * A folded log as every resolver member reads it: `states`, one per chain event, for the historic
 * key scan; `head`, the last of them merged with the current epoch, for every live answer (keys,
 * denials, members, saturation).
 */
export type FoldedView = { states: Array<KeyState>; head: KeyState }

/**
 * What every resolver member throws while the controller's current epoch is saturated, followed by
 * `: ` and the DID. A plain error, not `IssuerKeyNotFoundError`: nothing about the key failed, the
 * controller as a whole cannot be answered for, and `@kokuin/capability` denies on exactly that.
 */
export const EPOCH_SATURATED = 'controller epoch is saturated'

/** What `resolveMember` rejects a member with that is not live in the head's generation. */
export const MEMBER_NOT_EFFECTIVE = 'not an effective management member'

/** Historic membership refusals after a successful controller fold. */
export const MEMBER_NOT_HISTORIC = 'not a historic management member'

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
function headSigningKey(did: string, head: KeyState, kid?: string): string {
  const key = keyFromKid(did, kid)
  if (key == null) {
    const first = head.keys[0]
    if (first === undefined) {
      throw new IssuerKeyNotFoundError(`Controller ${did} has no signing key`)
    }
    return first
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
function historicSigningKey(did: string, { states, head }: FoldedView, kid?: string): string {
  const key = keyFromKid(did, kid)
  if (key == null) {
    const first = head.keys[0]
    if (first === undefined) {
      throw new IssuerKeyNotFoundError(`Controller ${did} has no signing key`)
    }
    return first
  }
  for (let i = states.length - 1; i >= 0; i--) {
    const state = states[i]
    if (state === undefined || state.gen !== head.gen) {
      break
    }
    if (state.keys.includes(key)) {
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
 * The signing key `header` names, out of an already-folded view. `historic` picks which question above
 * is asked, and defaults to the safe one.
 *
 * **A revoked key answers neither question.** A deny entry naming `#<key>` retires a key for material
 * it has *already* signed, and this is where that bites — every `did:kokuin:` signature check reaches a
 * resolved key through here, so the denial covers `verifyToken` on both `historic` settings, every
 * capability and revocation record `@kokuin/capability` verifies. The historic arm is the live one:
 * a revoked key is never in the head's `k` (the `KeyState.deny` invariant), so only the backwards
 * scan can select one, and without this `resolveHistoric` would accept a leaked key forever.
 *
 * The head arm cannot be reached from a log this package folded, but is not decoration: `view`
 * arrives from the caller, and the invariant is the fold's property, not the view's — a
 * caller-built state whose head publishes a key it also denies resolves to nothing here.
 *
 * **Evaluated against the head's deny set, never the position the key was selected at.** A denial is
 * about the key, not one event, and the position an artefact carries is author-supplied — else a
 * thief presents a token resolving at a position before the revoke. Deliberately *not* how a DID
 * denial behaves inside the fold, where `states[i]` is consulted at position `i` because "was this
 * author allowed to act *here*" is the whole question; the two rules answer different questions.
 * The head here is the chain's last state merged with the current epoch, so a key retired by an
 * epoch revoke is refused as surely as one a settlement checkpointed.
 */
export function signingKeyFrom({
  did,
  view,
  header,
  historic = false,
}: {
  did: string
  view: FoldedView
  header: ResolveIssuerHeader
  historic?: boolean
}): ResolvedSigningKey {
  const { head } = view
  if (head.keys.length === 0) {
    throw new Error(`Controller ${did} has no signing key`)
  }
  const selected = historic
    ? historicSigningKey(did, view, header.kid)
    : headSigningKey(did, head, header.kid)
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
 * The head's key agreement set, minus anything it has revoked. A deny entry may name an agreement key
 * as readily as a signing one (the target spelling is the key, not its purpose), and these are the keys
 * a *sender* encrypts to — encrypting to a revoked key is the one outcome a denial must prevent.
 *
 * Like the signing side, unreachable from a log this package folded (the `KeyState.deny` invariant)
 * but `head` arrives from the caller. Filtering to empty is the honest answer for a state that
 * denies everything it publishes: `@kokuin/jwe` then encrypts nothing, the fail-closed direction.
 */
export function agreementKeysFrom(did: string, head: KeyState): Array<ResolvedAgreementKey> {
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
 * The key and lease the head pins for one management member, or `IssuerKeyNotFoundError` carrying
 * {@link MEMBER_NOT_EFFECTIVE}.
 *
 * Every condition is asked of the head alone, the "answer for now" the interface demands: the member
 * must be present in it under the queried `add` digest, not removed and not targeted by a denial
 * (`effective`, which the fold computes with the one denial predicate it uses everywhere), and the
 * query's DID must be the member's under canonical DID equivalence — the long and short spellings of
 * one `did:peer:4` are one member; any other DID is another, even one carrying the same key.
 *
 * **The generation is part of the identity.** A reset carrying a snapshot keeps each member's `add`
 * reference, so incarnation alone cannot tell a grant minted before the reset from one minted after;
 * only `gen` can. A query naming any generation but the head's is refused, which is what makes a
 * reset kill every grant of the generation it replaces, carried members' included. The lease is
 * reported, never judged: the log has no clock, and bounding a grant by it is the verifier's step.
 *
 * `IssuerKeyNotFoundError` throughout, for the reason `keyFromKid` gives: the controller resolved and
 * what failed is a claim a token made about it, which must not read as the controller being
 * unresolvable.
 */
export function memberFrom(did: string, head: KeyState, query: MemberQuery): ResolvedMember {
  const refuse = (why: string) =>
    new IssuerKeyNotFoundError(`Controller ${did} ${query.did} is ${MEMBER_NOT_EFFECTIVE}: ${why}`)
  if (query.gen !== head.gen) {
    throw refuse(`generation ${String(query.gen)} is not the current ${head.gen}`)
  }
  const member = head.members.get(query.add)
  if (member === undefined) {
    throw refuse(`no member was added by ${query.add}`)
  }
  if (!member.effective) {
    throw refuse(member.removed ? 'removed' : 'denied')
  }
  if (normalizeDID(member.did) !== normalizeDID(query.did)) {
    throw refuse(`incarnation ${query.add} is another DID`)
  }
  const key = decodeKey(member.key)
  // Unreachable from a log this package folded (a member pin is Ed25519, adds and snapshots alike),
  // but `head` may be caller-built, and an agreement key must never come back as a signing one.
  if (key.alg !== 'EdDSA') {
    throw refuse(`pinned key is not Ed25519: ${key.alg}`)
  }
  return { key: { alg: key.alg, publicKey: key.publicKey }, lease: member.lease }
}

/** Removed incarnations retain authority for past-issued material until a generation reset. */
export function historicMemberFrom(
  did: string,
  view: FoldedView,
  query: MemberQuery,
): ResolvedMember {
  const refuse = (cause?: unknown) =>
    new IssuerKeyNotFoundError(`Controller ${did} ${query.did} is ${MEMBER_NOT_HISTORIC}`, {
      cause,
    })
  if (query.gen !== view.head.gen) throw refuse()
  const current = view.head.members.get(query.add)
  // A live denial is a compromise response, even when an earlier snapshot admitted the member.
  if (current !== undefined && !current.removed && !current.effective) throw refuse()
  const member =
    current ??
    view.states
      .findLast((state) => state.gen === query.gen && state.members.has(query.add))
      ?.members.get(query.add)
  if (member === undefined) throw refuse()
  if (!member.removed && [...view.head.deny].some((entry) => denialTargetsMember(entry, member)))
    throw refuse()
  if (!member.removed && !member.effective) throw refuse()
  try {
    if (normalizeDID(member.did) !== normalizeDID(query.did)) throw refuse()
    const key = decodeKey(member.key)
    if (key.alg !== 'EdDSA') throw refuse()
    return { key: { alg: key.alg, publicKey: key.publicKey }, lease: member.lease }
  } catch (cause) {
    throw refuse(cause)
  }
}

/**
 * A `DIDMethodResolver` answering every member out of the view `load` yields for the asked DID —
 * the one shape the live resolver and its frozen views share, so the
 * saturation refusal and the choice of which half of the view answers what are written once.
 *
 * **A saturated head answers nothing**, `resolveHistoric` included: the epoch's denials can no
 * longer be read, so any answer could be one a denial withdrew. The chain still folds, so root can
 * settle into a fresh epoch, and the refusal ends there.
 */
export function resolverOver(load: (did: string) => Promise<FoldedView>): DIDMethodResolver {
  async function live(did: string): Promise<FoldedView> {
    const view = await load(did)
    if (view.head.saturated) {
      throw new Error(`${EPOCH_SATURATED}: ${did}`)
    }
    return view
  }
  return {
    method: DID_METHOD,
    // The head's key set only: a profile that rotated away from a key answers "no" for it here, which
    // is what makes `rotate` retire a leaked authority key rather than add one beside it.
    async resolve(did: string, header: ResolveIssuerHeader = {}): Promise<ResolvedSigningKey> {
      return signingKeyFrom({ did, view: await live(did), header })
    },
    // Every key set within the current generation, for a caller verifying past-issued material. A
    // `rotate` must not invalidate those; a `reset` still does, and the scan stops at the generation
    // boundary. See {@link signingKeyFrom}.
    async resolveHistoric(
      did: string,
      header: ResolveIssuerHeader = {},
    ): Promise<ResolvedSigningKey> {
      return signingKeyFrom({ did, view: await live(did), header, historic: true })
    },
    async resolveDenySet(did: string): Promise<ReadonlySet<string>> {
      // The head's set, deliberately, not the state at any position a capability names: `iat` is
      // author-supplied and backdatable, so anchoring to it would let a revoked holder pick a
      // position at which it was not yet denied. The head merges the current epoch, so a denial
      // made there without root counts as soon as this party has seen it. Both spellings ride in it
      // (see `KeyState.deny`); the key half is enforced by `signingKeyFrom`, and the two forms
      // cannot collide. `load` throws `Unknown DID` rather than answering an empty (= "nobody
      // revoked") set.
      return (await live(did)).head.deny
    },
    async resolveAgreementKey(did: string): Promise<Array<ResolvedAgreementKey>> {
      // The head's set only, unlike `resolve`. A retired agreement key is a downgrade, not a grant
      // the profile already made: the recipient decrypts old ciphertexts by re-deriving from the
      // seed, never by resolution.
      return agreementKeysFrom(did, (await live(did)).head)
    },
    async resolveMemberHistoric(subject: string, member: MemberQuery): Promise<ResolvedMember> {
      return historicMemberFrom(subject, await live(subject), member)
    },
    async resolveMember(subject: string, member: MemberQuery): Promise<ResolvedMember> {
      return memberFrom(subject, (await live(subject)).head, member)
    },
  }
}
