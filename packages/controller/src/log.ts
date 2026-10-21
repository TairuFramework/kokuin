import { digestOf } from './canonical.js'
import { DEFAULT_EPOCH_LIMITS, type EpochLimits, foldEpoch } from './epoch.js'
import { type EpochEvent, isEpochEventShape, verifyEpochSignature } from './epoch-events.js'
import type { SignedEvent } from './events.js'
import { type FoldResult, foldLog, type KeyState } from './fold.js'
import { resolveBranches } from './supersede.js'

/**
 * Everything a controller's log holds: the root chain, which fixes the keys and every settlement, and
 * the epoch events that built up on the chain's last event since. They are separate lists because
 * they fold by different rules -- the chain is a sequence, order is meaning; the epoch is a set,
 * order is nothing -- and a presentation of one is no claim about the other.
 */
export type ControllerLog = { chain: Array<SignedEvent>; events: Array<SignedEvent<EpochEvent>> }

/** What a request carrying more epoch events than {@link MAX_LOG_EVENTS} fails with. */
export const LOG_TOO_LARGE = 'controller log exceeds request limits'

/** What an input that is not a {@link ControllerLog} at all fails with. */
export const MALFORMED_LOG = 'malformed log'

/**
 * Whether `value` has the two lists a log is made of. Only the outer shape: every entry is untrusted
 * and is checked by the fold that reads it, which reports a bad one rather than throwing.
 */
export function isControllerLog(value: unknown): value is ControllerLog {
  if (value == null || typeof value !== 'object') {
    return false
  }
  const log = value as Partial<Record<keyof ControllerLog, unknown>>
  return Array.isArray(log.chain) && Array.isArray(log.events)
}

/** What a resolver answers with when the loaded log loses to the one already seen. */
export const LOG_NOT_AUTHORITATIVE = 'the loaded log does not supersede the one already seen'

/** What a resolver answers with when the loaded log and the one already seen are a genuine fork. */
export const LOG_FORKED = 'the loaded log and the one already seen are a fork'

/** What {@link mergeLogs} and {@link pruneLog} fail with when no chain they were given folds. */
export const LOG_UNFOLDABLE = 'no controller log chain folds'

/**
 * Fold a log this party already holds: the chain through the full fold, the epoch with no request
 * limit. The request limit bounds what one *input* may make a verifier do; a held log is the union of
 * inputs that each passed it, already authenticated event by event, and may legitimately hold more
 * (a saturated epoch beside the history of earlier ones). Folding it through {@link foldLog} would
 * turn a long memory into `LOG_TOO_LARGE` — "no memory" — which is exactly the forgetting the history
 * exists to prevent.
 */
export function foldHeld(
  did: string,
  log: ControllerLog,
  limits?: Partial<EpochLimits>,
): FoldResult {
  if (!isControllerLog(log)) {
    return { ok: false, reason: MALFORMED_LOG, index: 0 }
  }
  const chain = foldLog(did, { chain: log.chain, events: [] })
  if (!chain.ok) {
    return chain
  }
  return withEpoch(did, chain.states, log.events, limits)
}

/** The chain's states merged with `events` as the current epoch, as {@link foldLog} reports it. */
export function withEpoch(
  did: string,
  states: Array<KeyState>,
  events: Array<unknown>,
  limits?: Partial<EpochLimits>,
): Extract<FoldResult, { ok: true }> {
  const merged = foldEpoch({ did, chainStates: states, events, limits })
  return {
    ok: true,
    states,
    head: merged.head,
    applied: merged.applied,
    pending: merged.pending,
    rejected: merged.rejected,
  }
}

/**
 * One copy of each event the fold applied, drawn from `presented`, in the fold's own order (parents
 * first). What may be remembered of an epoch, and nothing else: an entry the fold did not apply was
 * never authenticated, so it never reaches memory however it was presented.
 *
 * Two subtleties, both about copies. Copies of one body share a digest and differ only in signatures,
 * and the fold applies the event if *any* copy verifies — so "applied" does not say which copy did.
 * Keeping the first copy seen would let a relay put a forged copy ahead of the genuine one and have
 * memory keep the forgery, losing the event on the next fold. When a digest arrived under one
 * signature list that list is the one that verified; when under several, each is checked against the
 * signer the fold used (the chain head's keys for root, the incarnation's pinned key for a member)
 * until one passes.
 *
 * And saturation: an epoch holding more than `MAX_EPOCH_EVENTS` applied events is kept as only the
 * first `MAX_EPOCH_EVENTS + 1` of them. A prefix of the fold's topological order is closed under
 * ancestors, and an event's authorisation is a function of its ancestors alone, so the prefix refolds
 * to the same events applied — one more than the limit, saturated on every refold, never more held.
 */
export function appliedCopies(
  result: Extract<FoldResult, { ok: true }>,
  presented: Array<unknown>,
  limits?: Partial<EpochLimits>,
): Array<SignedEvent<EpochEvent>> {
  const maxEvents = limits?.MAX_EPOCH_EVENTS ?? DEFAULT_EPOCH_LIMITS.MAX_EPOCH_EVENTS
  const keep = result.head.saturated ? result.applied.slice(0, maxEvents + 1) : result.applied
  const wanted = new Set(keep)
  const copies = new Map<string, Array<SignedEvent<EpochEvent>>>()
  for (const entry of presented) {
    if (!isEpochEventShape(entry)) continue
    const digest = digestOf(entry.event)
    if (!wanted.has(digest)) continue
    const list = copies.get(digest)
    const copy = { event: entry.event, sigs: [...entry.sigs] }
    if (list === undefined) {
      copies.set(digest, [copy])
    } else if (!list.some((known) => sameSignatures(known.sigs, copy.sigs))) {
      list.push(copy)
    }
  }
  const kept: Array<SignedEvent<EpochEvent>> = []
  for (const digest of keep) {
    const list = copies.get(digest) ?? []
    const authentic = list.length === 1 ? list[0] : list.find((copy) => verifies(copy, result.head))
    if (authentic !== undefined) {
      kept.push(authentic)
    }
  }
  return kept
}

function sameSignatures(a: Array<string>, b: Array<string>): boolean {
  return a.length === b.length && a.every((sig, i) => sig === b[i])
}

/** Whether `copy` verifies under the signer the fold judged its event by. */
function verifies(copy: SignedEvent<EpochEvent>, head: KeyState): boolean {
  if (copy.event.by === undefined) {
    return verifyEpochSignature(copy, { rootKeys: head.keys })
  }
  const member = head.members.get(copy.event.by)
  return member !== undefined && verifyEpochSignature(copy, { memberKey: member.key })
}

/**
 * The chain two logs agree on: `b`'s when it extends (or is) `a`'s, otherwise whatever
 * {@link resolveBranches} names. Throws when that is nothing — a fork ({@link LOG_FORKED}) or no
 * chain that folds ({@link LOG_UNFOLDABLE}).
 */
function settledChain(
  did: string,
  a: Array<SignedEvent>,
  b: Array<SignedEvent>,
): Array<SignedEvent> {
  const left = foldLog(did, { chain: a, events: [] })
  const right = foldLog(did, { chain: b, events: [] })
  if (left.ok && right.ok) {
    const through = left.states[left.states.length - 1]?.digest
    if (right.states.some((state) => state.digest === through)) {
      return b
    }
  }
  const resolved = resolveBranches(did, [a, b])
  if (!resolved.ok) {
    throw new Error(`${resolved.failure === 'duplicity' ? LOG_FORKED : LOG_UNFOLDABLE}: ${did}`)
  }
  return resolved.winner
}

/**
 * Two views of one controller's log, combined. A pure merge, for a party joining what it holds with
 * what it was handed (a grant's proof, a peer's copy) before folding.
 *
 * The chain is settled by the branch rules: `b`'s when it extends `a`'s, else the winner of
 * {@link resolveBranches}, and a fork throws rather than merging two histories root never wrote as
 * one. The events are a union, deduplicated by digest *and signatures*: a copy carrying different
 * signatures is kept beside the first, since the fold applies an event when any copy verifies and
 * keeping only the first would let a forged copy shadow the genuine one. Entries that are not epoch
 * events at all are dropped; the fold would only have refused them.
 *
 * Nothing here authenticates an event. The result is input to a fold, not memory: persist what
 * `authoritativeLog` returns instead. A union of two inputs can exceed the request limit a single
 * input is held to, which {@link foldLog} then reports.
 */
export function mergeLogs(did: string, a: ControllerLog, b: ControllerLog): ControllerLog {
  const chain = settledChain(did, a.chain, b.chain)
  const events: Array<SignedEvent<EpochEvent>> = []
  const kept = new Map<string, Array<Array<string>>>()
  for (const entry of [...a.events, ...b.events]) {
    if (!isEpochEventShape(entry)) continue
    const digest = digestOf(entry.event)
    const signatures = kept.get(digest)
    if (signatures?.some((sigs) => sameSignatures(sigs, entry.sigs))) continue
    if (signatures === undefined) {
      kept.set(digest, [entry.sigs])
    } else {
      signatures.push(entry.sigs)
    }
    events.push({ event: entry.event, sigs: [...entry.sigs] })
  }
  return { chain, events }
}

/**
 * The least of a log that still folds to the same head: the inception, the current generation's
 * chain, and the current epoch's applied events.
 *
 * Earlier generations go because a reset chains to the inception, not to what preceded it, and the
 * generation's keys and tombstones are read off the generation alone. Unknown events the chain fold
 * skipped go too: they moved no state, so nothing chains to them. Earlier epochs' events go because
 * an event naming another epoch has no effect; unapplied ones because they were never authenticated.
 * A saturated epoch keeps exactly enough to stay saturated (see {@link appliedCopies}).
 *
 * Meant for a log this party already holds: the epoch is folded without the request limit (see
 * {@link foldHeld}). Throws {@link LOG_UNFOLDABLE} when the chain does not fold.
 */
export function pruneLog(did: string, log: ControllerLog): ControllerLog {
  const result = foldHeld(did, log)
  if (!result.ok) {
    throw new Error(`${LOG_UNFOLDABLE}: ${did}: ${result.reason} at event ${result.index}`)
  }
  const { states, head } = result
  const chain: Array<SignedEvent> = []
  for (const [i, signed] of log.chain.entries()) {
    const state = states[i]
    const prior = states[i - 1]
    if (i === 0 || (state?.gen === head.gen && state.digest !== prior?.digest)) {
      chain.push(signed)
    }
  }
  return { chain, events: appliedCopies(result, log.events) }
}
