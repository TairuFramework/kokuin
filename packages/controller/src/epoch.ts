import { digestOf } from './canonical.js'
import { type EpochEvent, isEpochEventShape, verifyEpochSignature } from './epoch-events.js'
import { keyFromTarget, type MemberEntry, type SignedEvent } from './events.js'
import type { KeyState, MemberState } from './fold.js'
import { MAX_EPOCH_EVENTS, MAX_FAILED_SIGNATURES } from './limits.js'
import {
  createDenialMatcher,
  type DenialMatcher,
  isRootKey,
  memberCarriesKey,
  type RootKeySet,
} from './members.js'

// Merging an epoch. The epoch's events are a set, not a sequence: nothing here may depend on the order
// they were presented in, how often, or which copy of a duplicate arrived first. The three places that
// could leak order are closed deliberately -- duplicates collapse by digest, ready events are taken
// by ascending digest, and an event's causal state is a function of its parents alone.

// Why a member-lifecycle event is refused. Each lands in `rejected` like any other refusal and never
// fails the fold; named so a test can tell which rule refused an event.

/** A member-signed add. Only root admits members, so sock-puppets cannot renew each other forever. */
export const ADD_NOT_ROOT = 'only root may add a member'

/** An add pinning a key on, or committed by, the generation's root chain, or the recovery key. */
export const ADD_KEY_IS_ROOT = 'member key is a root key'

/** An add whose DID is not a `did:key` or long-form `did:peer:4` carrying exactly its pin. */
export const ADD_DID_MISMATCH = 'member DID does not carry its key'

/** An add of a DID or key that a denial in its causal past targets. */
export const ADD_KEY_DENIED = 'member is denied in the causal state'

/** An add of a key an effective member of its causal past already pins. */
export const ADD_KEY_ALREADY_MEMBER = 'member key is already an effective member'

/** A member renewing an incarnation pinning its own key. */
export const SELF_RENEW = 'a member may not renew itself'

/** A member removing an incarnation pinning its own key. */
export const SELF_REMOVE = 'a member may not remove itself'

/** A renew or remove naming an add its causal past does not hold. */
export const UNKNOWN_MEMBER = 'target is not a member of the causal state'

/** A member revoke targeting an effective member of its causal past: members leave through remove. */
export const MEMBER_REVOKES_MEMBER = 'a member may not revoke a member'

/** A revoke denying a key the chain head publishes in `k` or `ka`. */
export const REVOKE_NAMES_ROOT_KEY = 'revoke targets a key the chain publishes'

/**
 * What a presentation fails with, as a whole, when the signatures on its copies that do not verify
 * exceed {@link MAX_FAILED_SIGNATURES}. A request limit, so it shares `LOG_TOO_LARGE`'s prefix.
 */
export const TOO_MANY_FAILED_SIGNATURES =
  'controller log exceeds request limits: too many signatures fail to verify'

/**
 * What one epoch accumulates. A join-semilattice: union of `added`/`removed`/`deny`, the maximum of
 * `leases` per incarnation, so merging concurrent branches in any order lands on one state.
 */
type EpochState = {
  added: Map<string, MemberEntry>
  removed: Set<string>
  leases: Map<string, number>
  deny: Set<string>
}

export type EpochLimits = { MAX_EPOCH_EVENTS: number }

/** What {@link foldEpoch} uses when a caller lowers nothing: pinned so a test can see it. */
export const DEFAULT_EPOCH_LIMITS: EpochLimits = { MAX_EPOCH_EVENTS }

export type FoldEpochParams = {
  did: string
  /** The chain's states, in order; the last is the anchor the epoch grew from. */
  chainStates: Array<KeyState>
  /** Untrusted: whatever was presented as epoch events. */
  events: Array<unknown>
  /**
   * Copies this verifier authenticated itself and kept: its own memory, never a presentation. A
   * trusted copy of an event of this epoch is taken as authentic without checking its signatures
   * again, and stands in for every presented copy of the same body, which are then not checked
   * either. Its signer is fixed by the epoch: a root event's keys are the chain event the epoch names,
   * a member event's key the add or snapshot entry its `by` digest names, so a copy that verified
   * once under this epoch verifies under it every time. Authorisation is still judged afresh.
   */
  trusted?: Array<unknown>
  /** Test-only: lowers a limit so saturation is reachable without thousands of signatures. */
  limits?: Partial<EpochLimits>
}

export type FoldEpochResult = {
  ok: true
  head: KeyState
  /** Digests of the events that applied, parents first, ties by ascending digest. */
  applied: Array<string>
  /** Well-formed events of this epoch whose parents never all applied. */
  pending: number
  /**
   * Refusals, counted by distinct event: an event presented any number of times counts once. An entry
   * that is not an epoch event at all has no digest to dedupe by and counts once per entry.
   */
  rejected: number
}

export type FoldEpochDetail = FoldEpochResult & {
  /** Why each refused event was refused, by digest. Entries that are not events at all have no digest. */
  reasons: Map<string, string>
  /**
   * The copy that verified, for each applied digest: what may be remembered of the event. A copy of a
   * body under other signatures shares its digest, so the digest alone does not say which to keep.
   */
  authentic: Map<string, SignedEvent<EpochEvent>>
}

/**
 * A presentation refused as a whole by a request limit on the work it asked for. Never a judgement on
 * any one event, so nothing about the epoch is learned from it.
 */
export type FoldEpochRefusal = { ok: false; reason: string }

function emptyState(): EpochState {
  return { added: new Map(), removed: new Set(), leases: new Map(), deny: new Set() }
}

function copyState(state: EpochState): EpochState {
  return {
    added: new Map(state.added),
    removed: new Set(state.removed),
    leases: new Map(state.leases),
    deny: new Set(state.deny),
  }
}

/** `into` becomes the join of itself and `other`. */
function joinInto(into: EpochState, other: EpochState): void {
  for (const [add, entry] of other.added) into.added.set(add, entry)
  for (const add of other.removed) into.removed.add(add)
  for (const [add, lease] of other.leases) {
    const current = into.leases.get(add)
    if (current === undefined || lease > current) into.leases.set(add, lease)
  }
  for (const entry of other.deny) into.deny.add(entry)
}

function anchorState(anchor: KeyState): EpochState {
  const state = emptyState()
  for (const member of anchor.members.values()) {
    state.added.set(member.add, {
      did: member.did,
      key: member.key,
      add: member.add,
      lease: member.lease,
    })
    if (member.removed) state.removed.add(member.add)
  }
  for (const entry of anchor.deny) state.deny.add(entry)
  return state
}

/**
 * Whether any denial in `deny` targets `member`: the one predicate, `denialTargetsMember`, through the
 * fold's memoised `matches`.
 */
function isDenied(deny: ReadonlySet<string>, member: MemberEntry, matches: DenialMatcher): boolean {
  for (const entry of deny) {
    if (matches(entry, member)) return true
  }
  return false
}

/**
 * Added, not removed, not denied: a member whose events the state authorises. The same test the head
 * applies to `MemberState.effective`, here asked of a causal state.
 */
function isEffective(state: EpochState, member: MemberEntry, matches: DenialMatcher): boolean {
  return !state.removed.has(member.add) && !isDenied(state.deny, member, matches)
}

type Candidate = {
  digest: string
  event: EpochEvent
  /** Every presented copy. They share a body and so a digest; they differ only in signatures. */
  copies: Array<SignedEvent<EpochEvent>>
  /** The copy whose signature verified, once {@link evaluate} has found one. */
  authentic?: SignedEvent<EpochEvent>
  /** A copy from the verifier's own memory: authentic without a check. */
  trusted?: SignedEvent<EpochEvent>
}

/**
 * Signatures on copies that failed to verify, over one fold. Each failing copy is charged for every
 * signature it carries, an upper bound on the Ed25519 work it cost (`verifySignatures` stops at the
 * first bad one). The total is a function of the presentation, not its order: the events evaluated are,
 * and so is each one's sorted walk of its copies in {@link canonicalCopy}. So stopping as soon as it
 * passes the limit refuses exactly the presentations that would have passed it anyway.
 */
type SignatureBudget = { failed: number }

function exhausted(budget: SignatureBudget): boolean {
  return budget.failed > MAX_FAILED_SIGNATURES
}

/** Why an event is refused outright, or `null` when it is a candidate to evaluate. */
function intrinsicRefusal(event: EpochEvent, did: string, anchor: KeyState): string | null {
  if (event.i !== did) return 'event names a different controller'
  if (event.g !== anchor.gen) return 'event names a different generation'
  return null
}

/**
 * Among the copies that verify, the one whose signature list sorts first, so two parties that saw the
 * same event under different valid signatures remember the same bytes, whatever order each saw them
 * in. Each distinct signature list is checked once, in ascending order, stopping at the first that
 * verifies: repeating a copy costs no extra verification, and neither does any list sorting after a
 * genuine one. Every list that fails is charged to `budget`; the walk stops once it is spent.
 */
function canonicalCopy(
  copies: Array<SignedEvent<EpochEvent>>,
  verifies: (copy: SignedEvent<EpochEvent>) => boolean,
  budget: SignatureBudget,
): SignedEvent<EpochEvent> | undefined {
  const distinct = new Map<string, SignedEvent<EpochEvent>>()
  for (const copy of copies) {
    // JSON, not a join: signatures are untrusted strings and may hold any separator, and a lossy key
    // would let a forgery spelling the genuine list as one string shadow it, checked first.
    const key = JSON.stringify(copy.sigs)
    if (!distinct.has(key)) distinct.set(key, copy)
  }
  for (const key of [...distinct.keys()].sort()) {
    const copy = distinct.get(key) as SignedEvent<EpochEvent>
    if (verifies(copy)) return copy
    budget.failed += copy.sigs.length
    if (exhausted(budget)) return undefined
  }
  return undefined
}

/**
 * Judge `event` against the state its parents established, and say what it adds. `null` reason means
 * it applies; the returned `effect` is then the event's own contribution.
 */
function evaluate(
  candidate: Candidate,
  causal: EpochState,
  anchor: KeyState,
  roots: RootKeySet,
  matches: DenialMatcher,
  budget: SignatureBudget,
): { reason: string } | { effect: EpochState } {
  const { event, digest } = candidate
  // A copy of the same body under a different signature is not a different event, so the event is
  // authentic if any presented copy is. Judging only the first would let a forged copy shadow the
  // genuine one depending on arrival order. A trusted copy was judged so when it was kept.
  const authenticate = (verifies: (copy: SignedEvent<EpochEvent>) => boolean) =>
    candidate.trusted ?? canonicalCopy(candidate.copies, verifies, budget)
  let signer: MemberEntry | null = null
  if (event.by === undefined) {
    candidate.authentic = authenticate((c) => verifyEpochSignature(c, { rootKeys: anchor.keys }))
    if (candidate.authentic === undefined) {
      return { reason: 'invalid root signature' }
    }
  } else {
    const member = causal.added.get(event.by)
    if (member === undefined) return { reason: 'signer is not a member of the causal state' }
    if (causal.removed.has(event.by)) return { reason: 'signer was removed in the causal state' }
    if (isDenied(causal.deny, member, matches))
      return { reason: 'signer is denied in the causal state' }
    candidate.authentic = authenticate((c) => verifyEpochSignature(c, { memberKey: member.key }))
    if (candidate.authentic === undefined) {
      return { reason: 'invalid member signature' }
    }
    signer = member
  }

  const effect = emptyState()
  switch (event.t) {
    case 'rev': {
      // A member removes members; it does not deny them. Denial dominates membership and a removal
      // does not, so a revoke would be a removal that skips the self-remove rule and that root's own
      // add could never undo short of a settlement: a denied key or DID refuses every later add of it.
      // Every member of the causal past is shielded, removed or denied ones included -- otherwise one
      // member removes another and a second denies it on top, and root can no longer re-admit that
      // key under any DID. Root alone may deny a member it can see. The shield is the causal past
      // only: a member root adds concurrently is not in it, so a member on a branch that has not seen
      // the add can deny its key or DID, and root's re-add is refused (`ADD_KEY_DENIED`) until a
      // settlement drops the denial. An accepted stolen-member risk; see the security reference.
      if (signer !== null) {
        for (const member of causal.added.values()) {
          if (matches(event.x, member)) {
            return { reason: MEMBER_REVOKES_MEMBER }
          }
        }
      }
      // Any signer, root included: a denied published key would leave a head whose `k` or `ka`
      // resolves to nothing (the `KeyState.deny` invariant). Retired keys may be denied.
      const key = keyFromTarget(event.x)
      if (key != null && (anchor.keys.includes(key) || anchor.agreement.includes(key))) {
        return { reason: REVOKE_NAMES_ROOT_KEY }
      }
      effect.deny.add(event.x)
      return { effect }
    }
    case 'add': {
      if (signer !== null) return { reason: ADD_NOT_ROOT }
      const entry: MemberEntry = { did: event.did, key: event.key, add: digest, lease: event.lease }
      // Ed25519 only, and the DID carries exactly the pin: a grant verifier that reads the DID and
      // one that reads the pin must agree on the key. A non-Ed25519 pin fails here too.
      if (!memberCarriesKey(entry.did, entry.key)) return { reason: ADD_DID_MISMATCH }
      // The same disjointness a snapshot obeys, by the same predicate: no management device holds a
      // root key, so member authority and root authority are never mistaken for each other.
      if (isRootKey(entry.key, roots)) return { reason: ADD_KEY_IS_ROOT }
      // Judged against the causal past only. A denial concurrent with the add does not refuse it --
      // neither may be dropped for arriving second -- it makes the merged member non-effective.
      if (isDenied(causal.deny, entry, matches)) return { reason: ADD_KEY_DENIED }
      // One key, one live incarnation along any causal line: a second effective add of the same key
      // would be an alias whose renewals the self-renew rule could only catch by key anyway, and
      // root has no reason to issue one. Concurrent adds (a retry) cannot see each other, so both
      // stand; pinned-key equality is what keeps them from renewing each other.
      for (const member of causal.added.values()) {
        if (member.key === entry.key && isEffective(causal, member, matches)) {
          return { reason: ADD_KEY_ALREADY_MEMBER }
        }
      }
      effect.added.set(digest, entry)
      return { effect }
    }
    case 'ren':
    case 'rmv': {
      // An incarnation is its add digest: a renew or remove of an add the causal past never held
      // has no target, and a delayed one of an old incarnation never reaches a re-add of its key.
      const target = causal.added.get(event.add)
      if (target === undefined) return { reason: UNKNOWN_MEMBER }
      // "Another member" is another pinned key, whatever the DID or incarnation: one key added
      // twice (as a `did:key` and as a peer DID, or by a retried add) is still one device.
      if (signer !== null && signer.key === target.key) {
        return { reason: event.t === 'ren' ? SELF_RENEW : SELF_REMOVE }
      }
      // Neither looks at whether the target is removed: removal dominates renewal at the join, so a
      // renewal of a removed member is harmless and refusing it would make the outcome depend on
      // which branch the renewer happened to see.
      if (event.t === 'ren') effect.leases.set(event.add, event.lease)
      else effect.removed.add(event.add)
      return { effect }
    }
    default:
      return { reason: 'unknown epoch event type' }
  }
}

/** Insert `digest` into `sorted` keeping ascending order. */
function insertSorted(sorted: Array<string>, digest: string): void {
  let lo = 0
  let hi = sorted.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if ((sorted[mid] as string) < digest) lo = mid + 1
    else hi = mid
  }
  sorted.splice(lo, 0, digest)
}

/**
 * Merge the current epoch into the chain's last state. Total: whatever `events` holds, the result is
 * a head or a refusal, never a throw -- an entry that is not a valid epoch event is counted and
 * dropped. The one refusal is the request limit on failed signatures ({@link TOO_MANY_FAILED_SIGNATURES}),
 * which `trusted` copies never count towards.
 */
export function foldEpochDetailed(params: FoldEpochParams): FoldEpochDetail | FoldEpochRefusal {
  const { did, chainStates, events } = params
  const maxEvents = params.limits?.MAX_EPOCH_EVENTS ?? DEFAULT_EPOCH_LIMITS.MAX_EPOCH_EVENTS
  const anchor = chainStates[chainStates.length - 1] as KeyState
  const reasons = new Map<string, string>()
  let rejected = 0

  // Digests of chain events: a parent naming one is a cross-epoch parent, not a missing one.
  const chainDigests = new Set(chainStates.map((state) => state.digest))

  // The root keys an add's pin must avoid: every `k`/`ka`/`n` on the anchor's generation, read off
  // the chain alone as the rotate's snapshot check reads them, so an add and a snapshot refuse the
  // same pins. A reset opens a generation, so earlier generations' keys are not counted -- they
  // cannot sign for this one. Skipped states repeat their prior, which the sets absorb.
  const rootKeys = new Set<string>()
  const commitments = new Set<string>()
  for (const state of chainStates) {
    if (state.gen !== anchor.gen) continue
    for (const key of [...state.keys, ...state.agreement]) rootKeys.add(key)
    for (const commitment of state.next) commitments.add(commitment)
  }
  const roots: RootKeySet = { keys: rootKeys, commitments, recovery: anchor.recovery }
  // One canonicalisation per distinct DID for the whole fold: see `createDenialMatcher`.
  const matches = createDenialMatcher()

  // 1. Triage. Dedupe by digest; an event of another epoch is ignored silently (its effect is in the
  // newer snapshot or was dropped by it), but it is remembered by digest so that naming it as a
  // parent reads as a cross-epoch parent rather than a missing one.
  const candidates = new Map<string, Candidate>()
  const otherEpochs = new Set<string>()
  const counted = new Set<string>()
  // Memory first, so every presented copy of a held body finds its trusted copy already there. Held
  // copies are this verifier's own, so one that is not of this epoch, or not an epoch event at all
  // (a corrupted store), is simply not used: it is no refusal of anything presented.
  for (const entry of params.trusted ?? []) {
    if (!isEpochEventShape(entry) || entry.event.e !== anchor.epoch) continue
    if (intrinsicRefusal(entry.event, did, anchor) !== null) continue
    const digest = digestOf(entry.event)
    if (!candidates.has(digest)) {
      candidates.set(digest, { digest, event: entry.event, copies: [entry], trusted: entry })
    }
  }
  for (const entry of events) {
    if (!isEpochEventShape(entry)) {
      rejected++
      continue
    }
    const digest = digestOf(entry.event)
    if (entry.event.e !== anchor.epoch) {
      otherEpochs.add(digest)
      continue
    }
    const refusal = intrinsicRefusal(entry.event, did, anchor)
    if (refusal !== null) {
      reasons.set(digest, refusal)
      if (!counted.has(digest)) {
        counted.add(digest)
        rejected++
      }
      continue
    }
    const existing = candidates.get(digest)
    if (existing === undefined) {
      candidates.set(digest, { digest, event: entry.event, copies: [entry] })
    } else if (existing.trusted === undefined) {
      existing.copies.push(entry)
    }
  }

  // Parents. A parent that is neither the anchor nor a candidate is judged by what it is: another
  // epoch's event or a chain event refuses the child; a refused same-epoch event leaves it pending;
  // anything else is simply not here yet, which is also pending.
  //
  // Two passes: every candidate's parents are classified before any edge is registered, so an event
  // refused for a cross-epoch parent never leaves an edge behind for a surviving parent to follow.
  const crossEpoch: Array<string> = []
  for (const candidate of candidates.values()) {
    if (
      candidate.event.p.some(
        (parent) =>
          parent !== anchor.epoch &&
          !candidates.has(parent) &&
          (otherEpochs.has(parent) || chainDigests.has(parent)),
      )
    ) {
      crossEpoch.push(candidate.digest)
    }
  }
  for (const digest of crossEpoch) {
    candidates.delete(digest)
    reasons.set(digest, 'event lists a parent outside its epoch')
    rejected++
  }
  const children = new Map<string, Array<string>>()
  const waiting = new Map<string, number>()
  const ready: Array<string> = []
  for (const candidate of candidates.values()) {
    let waits = 0
    for (const parent of candidate.event.p) {
      if (parent === anchor.epoch) continue
      waits++
      if (candidates.has(parent)) {
        const list = children.get(parent)
        if (list === undefined) children.set(parent, [candidate.digest])
        else list.push(candidate.digest)
      }
      // Anything else -- a refused event, an absent one -- never applies, so this edge never clears.
    }
    waiting.set(candidate.digest, waits)
    if (waits === 0) insertSorted(ready, candidate.digest)
  }

  // 2-4. Kahn's algorithm, smallest ready digest first. `after` is memoised per digest and dropped
  // once its last child has read it. That frees a plain chain, but not every shape: a chain e1..en
  // with a side event per ei that also names en keeps about n/2 states alive until en applies. Work
  // and memory are bounded by the request limit (MAX_LOG_EVENTS events of at most MAX_EVENT_PARENTS
  // parents each), roughly events x parents x state size, not by this release.
  const anchorAfter = anchorState(anchor)
  const after = new Map<string, EpochState>()
  const unread = new Map<string, number>()
  const applied: Array<string> = []
  const authentic = new Map<string, SignedEvent<EpochEvent>>()
  const union = copyState(anchorAfter)
  const budget: SignatureBudget = { failed: 0 }
  let evaluated = 0

  while (ready.length > 0) {
    const digest = ready.shift() as string
    // `ready` only ever holds candidates, and none is deleted once edges are registered.
    const candidate = candidates.get(digest) as Candidate
    evaluated++

    const causal = emptyState()
    let seenAnchor = false
    for (const parent of candidate.event.p) {
      if (parent === anchor.epoch) {
        if (!seenAnchor) joinInto(causal, anchorAfter)
        seenAnchor = true
        continue
      }
      const parentAfter = after.get(parent)
      if (parentAfter !== undefined) joinInto(causal, parentAfter)
      const left = (unread.get(parent) ?? 1) - 1
      if (left <= 0) {
        unread.delete(parent)
        after.delete(parent)
      } else {
        unread.set(parent, left)
      }
    }

    const outcome = evaluate(candidate, causal, anchor, roots, matches, budget)
    if (exhausted(budget)) {
      return { ok: false, reason: TOO_MANY_FAILED_SIGNATURES }
    }
    if ('reason' in outcome) {
      rejected++
      reasons.set(digest, outcome.reason)
      continue
    }
    applied.push(digest)
    if (candidate.authentic !== undefined) authentic.set(digest, candidate.authentic)
    joinInto(union, outcome.effect)
    const kids = children.get(digest)
    if (kids !== undefined && kids.length > 0) {
      joinInto(causal, outcome.effect)
      after.set(digest, causal)
      unread.set(digest, kids.length)
      for (const kid of kids) {
        // Edges are registered only between candidates, each with its own count.
        const left = waiting.get(kid) as number
        waiting.set(kid, left - 1)
        if (left === 1) insertSorted(ready, kid)
      }
    }
  }

  const pending = candidates.size - evaluated
  const appliedSet = new Set(applied)
  for (const digest of candidates.keys()) {
    if (!appliedSet.has(digest) && !reasons.has(digest)) {
      reasons.set(digest, 'a parent is missing or was not applied')
    }
  }

  const members = new Map<string, MemberState>()
  for (const [add, entry] of union.added) {
    const lease = Math.max(entry.lease, union.leases.get(add) ?? 0)
    const removed = union.removed.has(add)
    const effective = !removed && !isDenied(union.deny, entry, matches)
    members.set(add, { ...entry, lease, removed, effective })
  }
  return {
    ok: true,
    head: {
      ...anchor,
      deny: union.deny,
      members,
      saturated: applied.length > maxEvents,
    },
    applied,
    pending,
    rejected,
    reasons,
    authentic,
  }
}

/** {@link foldEpochDetailed} without the per-event reasons and copies. */
export function foldEpoch(params: FoldEpochParams): FoldEpochResult | FoldEpochRefusal {
  const detail = foldEpochDetailed(params)
  if (!detail.ok) return detail
  const { reasons: _reasons, authentic: _authentic, ...result } = detail
  return result
}
