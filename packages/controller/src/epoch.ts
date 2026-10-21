import { digestOf } from './canonical.js'
import { type EpochEvent, isEpochEventShape, verifyEpochSignature } from './epoch-events.js'
import { keyFromTarget, type MemberEntry, type SignedEvent } from './events.js'
import type { KeyState, MemberState } from './fold.js'
import { MAX_EPOCH_EVENTS } from './limits.js'
import { denialTargetsMember } from './members.js'

// Merging an epoch. The epoch's events are a set, not a sequence: nothing here may depend on the order
// they were presented in, how often, or which copy of a duplicate arrived first. The three places that
// could leak order are closed deliberately -- duplicates collapse by digest, ready events are taken
// by ascending digest, and an event's causal state is a function of its parents alone.

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

export type FoldEpochParams = {
  did: string
  /** The chain's states, in order; the last is the anchor the epoch grew from. */
  chainStates: Array<KeyState>
  /** Untrusted: whatever was presented as epoch events. */
  events: Array<unknown>
  /** Test-only: lowers a limit so saturation is reachable without thousands of signatures. */
  limits?: Partial<EpochLimits>
}

export type FoldEpochResult = {
  head: KeyState
  /** Digests of the events that applied, parents first, ties by ascending digest. */
  applied: Array<string>
  /** Well-formed events of this epoch whose parents never all applied. */
  pending: number
  /** Entries that are not valid epoch events, or events the fold refused. */
  rejected: number
}

export type FoldEpochDetail = FoldEpochResult & {
  /** Why each refused event was refused, by digest. Entries that are not events at all have no digest. */
  reasons: Map<string, string>
}

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

/** Whether any denial in `deny` targets `member`: the one predicate, see `denialTargetsMember`. */
function isDenied(deny: ReadonlySet<string>, member: MemberEntry): boolean {
  for (const entry of deny) {
    if (denialTargetsMember(entry, member)) return true
  }
  return false
}

type Candidate = {
  digest: string
  event: EpochEvent
  /** Every presented copy. They share a body and so a digest; they differ only in signatures. */
  copies: Array<SignedEvent<EpochEvent>>
}

/** Why an event is refused outright, or `null` when it is a candidate to evaluate. */
function intrinsicRefusal(event: EpochEvent, did: string, anchor: KeyState): string | null {
  if (event.i !== did) return 'event names a different controller'
  if (event.g !== anchor.gen) return 'event names a different generation'
  return null
}

/**
 * Judge `event` against the state its parents established, and say what it adds. `null` reason means
 * it applies; the returned `effect` is then the event's own contribution.
 */
function evaluate(
  candidate: Candidate,
  causal: EpochState,
  anchor: KeyState,
): { reason: string } | { effect: EpochState } {
  const { event, digest } = candidate
  // A copy of the same body under a different signature is not a different event, so the event is
  // authentic if any presented copy is. Judging only the first would let a forged copy shadow the
  // genuine one depending on arrival order.
  let signer: MemberEntry | null = null
  if (event.by === undefined) {
    if (!candidate.copies.some((c) => verifyEpochSignature(c, { rootKeys: anchor.keys }))) {
      return { reason: 'invalid root signature' }
    }
  } else {
    const member = causal.added.get(event.by)
    if (member === undefined) return { reason: 'signer is not a member of the causal state' }
    if (causal.removed.has(event.by)) return { reason: 'signer was removed in the causal state' }
    if (isDenied(causal.deny, member)) return { reason: 'signer is denied in the causal state' }
    if (!candidate.copies.some((c) => verifyEpochSignature(c, { memberKey: member.key }))) {
      return { reason: 'invalid member signature' }
    }
    signer = member
  }

  const effect = emptyState()
  switch (event.t) {
    case 'rev': {
      const key = keyFromTarget(event.x)
      if (key != null && (anchor.keys.includes(key) || anchor.agreement.includes(key))) {
        return { reason: 'revoke targets a key the chain publishes' }
      }
      effect.deny.add(event.x)
      return { effect }
    }
    // Root-only for now: a member-signed add, renew or remove is not authorised.
    case 'add':
    case 'ren':
    case 'rmv': {
      if (signer !== null) return { reason: 'only root may add, renew or remove a member' }
      if (event.t === 'add') {
        effect.added.set(digest, {
          did: event.did,
          key: event.key,
          add: digest,
          lease: event.lease,
        })
      } else if (event.t === 'ren') {
        effect.leases.set(event.add, event.lease)
      } else {
        effect.removed.add(event.add)
      }
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
 * a head, never a throw -- an entry that is not a valid epoch event is counted and dropped.
 */
export function foldEpochDetailed(params: FoldEpochParams): FoldEpochDetail {
  const { did, chainStates, events } = params
  const maxEvents = params.limits?.MAX_EPOCH_EVENTS ?? MAX_EPOCH_EVENTS
  const anchor = chainStates[chainStates.length - 1] as KeyState
  const reasons = new Map<string, string>()
  let rejected = 0

  // Digests of chain events: a parent naming one is a cross-epoch parent, not a missing one.
  const chainDigests = new Set(chainStates.map((state) => state.digest))

  // 1. Triage. Dedupe by digest; an event of another epoch is ignored silently (its effect is in the
  // newer snapshot or was dropped by it), but it is remembered by digest so that naming it as a
  // parent reads as a cross-epoch parent rather than a missing one.
  const candidates = new Map<string, Candidate>()
  const otherEpochs = new Set<string>()
  const counted = new Set<string>()
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
    } else {
      existing.copies.push(entry)
    }
  }

  // Parents. A parent that is neither the anchor nor a candidate is judged by what it is: another
  // epoch's event or a chain event refuses the child; a refused same-epoch event leaves it pending;
  // anything else is simply not here yet, which is also pending.
  const children = new Map<string, Array<string>>()
  const waiting = new Map<string, number>()
  const ready: Array<string> = []
  for (const candidate of [...candidates.values()].sort((x, y) => (x.digest < y.digest ? -1 : 1))) {
    let crossEpoch = false
    let waits = 0
    for (const parent of candidate.event.p) {
      if (parent === anchor.epoch) continue
      if (candidates.has(parent)) {
        waits++
        const list = children.get(parent)
        if (list === undefined) children.set(parent, [candidate.digest])
        else list.push(candidate.digest)
      } else if (otherEpochs.has(parent) || chainDigests.has(parent)) {
        crossEpoch = true
      } else {
        // Refused same-epoch events and absent ones alike never apply, so this edge never clears.
        waits++
      }
    }
    if (crossEpoch) {
      candidates.delete(candidate.digest)
      reasons.set(candidate.digest, 'event lists a parent outside its epoch')
      rejected++
      continue
    }
    waiting.set(candidate.digest, waits)
  }
  // A child of an event refused above keeps its edge to it, which never clears: it stays pending.
  for (const [digest, waits] of waiting) {
    if (waits === 0 && candidates.has(digest)) insertSorted(ready, digest)
  }

  // 2-4. Kahn's algorithm, smallest ready digest first. `after` is memoised per digest and dropped
  // once its last child has read it, so a long chain of events never holds quadratic state.
  const anchorAfter = anchorState(anchor)
  const after = new Map<string, EpochState>()
  const unread = new Map<string, number>()
  const applied: Array<string> = []
  const union = copyState(anchorAfter)
  let evaluated = 0

  while (ready.length > 0) {
    const digest = ready.shift() as string
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

    const outcome = evaluate(candidate, causal, anchor)
    if ('reason' in outcome) {
      rejected++
      reasons.set(digest, outcome.reason)
      continue
    }
    applied.push(digest)
    joinInto(union, outcome.effect)
    const kids = children.get(digest)
    if (kids !== undefined && kids.length > 0) {
      joinInto(causal, outcome.effect)
      after.set(digest, causal)
      unread.set(digest, kids.length)
      for (const kid of kids) {
        const left = (waiting.get(kid) ?? 1) - 1
        waiting.set(kid, left)
        if (left === 0) insertSorted(ready, kid)
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

  if (applied.length === 0) {
    return { head: anchor, applied, pending, rejected, reasons }
  }

  const members = new Map<string, MemberState>()
  for (const [add, entry] of union.added) {
    const lease = Math.max(entry.lease, union.leases.get(add) ?? 0)
    const removed = union.removed.has(add)
    const effective = !removed && !isDenied(union.deny, entry)
    members.set(add, { ...entry, lease, removed, effective })
  }
  return {
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
  }
}

/** {@link foldEpochDetailed} without the per-event reasons. */
export function foldEpoch(params: FoldEpochParams): FoldEpochResult {
  const { reasons: _reasons, ...result } = foldEpochDetailed(params)
  return result
}
