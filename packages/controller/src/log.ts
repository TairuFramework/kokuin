import type { CryptoOptions } from '@kokuin/token'

import { digestOf } from './canonical.js'
import { DEFAULT_EPOCH_LIMITS, type EpochLimits, foldEpochDetailed } from './epoch.js'
import { type EpochEvent, isEpochEventShape } from './epoch-events.js'
import type { SignedEvent } from './events.js'
import { type FoldResult, foldLog, type KeyState } from './fold.js'
import { MAX_EPOCH_EVENTS, MAX_EVENT_PARENTS, MAX_LOG_EVENTS } from './limits.js'
import { snapshotLog } from './log-snapshot.js'
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

/**
 * Request limit for a log this party holds or is about to merge into what it holds: one saturated
 * epoch kept in memory (`MAX_EPOCH_EVENTS + 1` events) plus one presentation (`MAX_LOG_EVENTS`).
 * What {@link epochHeads}, {@link pruneLog} and {@link mergeLogs} accept; anything larger is no log
 * a verifier could have built and fails `LOG_TOO_LARGE`.
 */
const MAX_HELD_EVENTS = MAX_EPOCH_EVENTS + 1 + MAX_LOG_EVENTS

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

/** A fold of a held log, with the copy of each applied event whose signature the fold verified. */
export type HeldFold = {
  result: Extract<FoldResult, { ok: true }>
  /** Per applied digest, the copy that verified. See {@link appliedCopies}. */
  authentic: ReadonlyMap<string, SignedEvent<EpochEvent>>
}

/**
 * Fold a log this party already holds: the chain through the full fold, the epoch under the held
 * request limit rather than `MAX_LOG_EVENTS`. The request limit bounds what one *input* may make a
 * verifier do; a held log is the union of inputs that each passed it and is already bounded by what
 * memory keeps (one epoch, at most `MAX_EPOCH_EVENTS + 1` events once saturated), but the union with a
 * fresh presentation can exceed it. Folding through {@link foldLog} would turn that into
 * `LOG_TOO_LARGE` — "no memory" — which is exactly the forgetting the history exists to prevent.
 *
 * Nothing in `log` is trusted: every signature is checked, under the failed-signature limit.
 */
export async function foldHeld(
  did: string,
  input: ControllerLog,
  limits?: Partial<EpochLimits>,
  options: CryptoOptions = {},
): Promise<HeldFold | Extract<FoldResult, { ok: false }>> {
  if (!isControllerLog(input)) {
    return { ok: false, reason: MALFORMED_LOG, index: 0 }
  }
  if (input.events.length > MAX_HELD_EVENTS) {
    return { ok: false, reason: LOG_TOO_LARGE, index: -1 }
  }
  const log = snapshotLog(input)
  const chain = await foldLog(did, { chain: log.chain, events: [] }, options)
  if (!chain.ok) {
    return chain
  }
  return await withEpoch(did, chain.states, log.events, limits, undefined, options)
}

/**
 * The chain's states merged with `events` as the current epoch, as {@link foldLog} reports it.
 * `trusted` is this party's own memory (see `FoldEpochParams.trusted`), never a presentation. Refused,
 * at index -1, when `events` passes the failed-signature limit.
 */
export async function withEpoch(
  did: string,
  states: Array<KeyState>,
  events: Array<unknown>,
  limits?: Partial<EpochLimits>,
  trusted?: Array<unknown>,
  options: CryptoOptions = {},
): Promise<HeldFold | Extract<FoldResult, { ok: false }>> {
  const merged = await foldEpochDetailed({
    ...options,
    did,
    chainStates: states,
    events,
    limits,
    trusted,
  })
  if (!merged.ok) {
    return { ok: false, reason: merged.reason, index: -1 }
  }
  return {
    result: {
      ok: true,
      states,
      head: merged.head,
      applied: merged.applied,
      pending: merged.pending,
      rejected: merged.rejected,
    },
    authentic: merged.authentic,
  }
}

/**
 * The parents an epoch event built now should name: the current epoch's applied events that no
 * applied event names as a parent, sorted ascending, or `[head.epoch]` when none applied. An event
 * naming every tip is causally after everything its author has seen, and authorisation is judged
 * against exactly that causal past -- naming fewer leaves the author's own view out of it.
 *
 * Pending and rejected events are never heads: they are not part of the folded epoch. Throws, with
 * the fold's reason, when the log does not fold; a builder has nothing to extend then.
 *
 * At most `MAX_EVENT_PARENTS` are returned, so the answer is always a valid `parents`: when the epoch
 * has more tips (concurrent events are free to make), the smallest digests. The event built on them is
 * causally after those alone; the rest stay tips, and the next event built from `epochHeads` names
 * them, so repeated building folds every tip in. Throws `LOG_TOO_LARGE` on a log larger than any a
 * verifier holds.
 */
export async function epochHeads(
  did: string,
  log: ControllerLog,
  options: CryptoOptions = {},
): Promise<Array<string>> {
  const held = await foldHeld(did, log, undefined, options)
  if ('ok' in held) {
    throw new Error(`${held.reason}: ${did}`)
  }
  const { result, authentic } = held
  const named = new Set<string>()
  for (const digest of result.applied) {
    for (const parent of authentic.get(digest)?.event.p ?? []) {
      named.add(parent)
    }
  }
  const heads = result.applied.filter((digest) => !named.has(digest)).sort()
  return heads.length === 0 ? [result.head.epoch] : heads.slice(0, MAX_EVENT_PARENTS)
}

/**
 * One copy of each event the fold applied, in the fold's own order (parents first): all that may be
 * remembered of an epoch. An entry the fold did not apply was never authenticated, so it never
 * reaches memory however it was presented.
 *
 * The copy is the one the fold itself verified, never re-derived here. Copies of one body share a
 * digest and differ only in signatures, and the fold applies the event if *any* copy verifies — so
 * "applied" alone does not say which copy to keep. Keeping the first one presented would let a relay
 * put a forged copy ahead of the genuine one and have memory keep the forgery, losing the event on
 * the next fold; re-checking signatures against a signer looked up afresh would answer a subtly
 * different question from the one the fold answered, and drop the event whenever they disagree.
 *
 * Saturation: an epoch holding more than `MAX_EPOCH_EVENTS` applied events is kept as only the
 * first `MAX_EPOCH_EVENTS + 1` of them. A prefix of the fold's topological order is closed under
 * ancestors, and an event's authorisation is a function of its ancestors alone, so the prefix refolds
 * to the same events applied — one more than the limit, saturated on every refold, never more held.
 */
export function appliedCopies(
  { result, authentic }: HeldFold,
  limits?: Partial<EpochLimits>,
): Array<SignedEvent<EpochEvent>> {
  const maxEvents = limits?.MAX_EPOCH_EVENTS ?? DEFAULT_EPOCH_LIMITS.MAX_EPOCH_EVENTS
  const keep = result.head.saturated ? result.applied.slice(0, maxEvents + 1) : result.applied
  const kept: Array<SignedEvent<EpochEvent>> = []
  for (const digest of keep) {
    const copy = authentic.get(digest)
    if (copy !== undefined) {
      kept.push({ event: copy.event, sigs: [...copy.sigs] })
    }
  }
  return kept
}

function sameSignatures(a: Array<string>, b: Array<string>): boolean {
  return a.length === b.length && a.every((sig, i) => sig === b[i])
}

/**
 * The chain two logs agree on: `b`'s when it extends (or is) `a`'s, otherwise whatever
 * {@link resolveBranches} names. Throws when that is nothing — a fork ({@link LOG_FORKED}) or no
 * chain that folds ({@link LOG_UNFOLDABLE}).
 */
async function settledChain(
  did: string,
  a: Array<SignedEvent>,
  b: Array<SignedEvent>,
  options: CryptoOptions = {},
): Promise<Array<SignedEvent>> {
  const left = await foldLog(did, { chain: a, events: [] }, options)
  const right = await foldLog(did, { chain: b, events: [] }, options)
  if (left.ok && right.ok) {
    const through = left.states[left.states.length - 1]?.digest
    if (right.states.some((state) => state.digest === through)) {
      return b
    }
  }
  const resolved = await resolveBranches(did, [a, b], options)
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
 * input is held to, which {@link foldLog} then reports. Each input may be at most what a verifier
 * holds plus one presentation; a larger one throws `LOG_TOO_LARGE` before any work.
 */
export async function mergeLogs(
  did: string,
  left: ControllerLog,
  right: ControllerLog,
  options: CryptoOptions = {},
): Promise<ControllerLog> {
  if (left.events.length > MAX_HELD_EVENTS || right.events.length > MAX_HELD_EVENTS) {
    throw new Error(`${LOG_TOO_LARGE}: ${did}`)
  }
  const a = snapshotLog(left)
  const b = snapshotLog(right)
  const chain = await settledChain(did, a.chain, b.chain, options)
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
 * Meant for a log this party already holds: the epoch is folded under the held request limit, not
 * `MAX_LOG_EVENTS` (see {@link foldHeld}). Throws {@link LOG_UNFOLDABLE} when the chain does not fold,
 * and the request limit's reason when the log passes one.
 */
export async function pruneLog(
  did: string,
  input: ControllerLog,
  options: CryptoOptions = {},
): Promise<ControllerLog> {
  const log = snapshotLog(input)
  const held = await foldHeld(did, log, undefined, options)
  if (!('result' in held)) {
    // Index -1 is a request limit: the chain may fold fine, the log is refused as too much work.
    throw new Error(
      held.index === -1
        ? `${held.reason}: ${did}`
        : `${LOG_UNFOLDABLE}: ${did}: ${held.reason} at event ${held.index}`,
    )
  }
  const { states, head } = held.result
  const chain: Array<SignedEvent> = []
  for (const [i, signed] of log.chain.entries()) {
    const state = states[i]
    const prior = states[i - 1]
    if (i === 0 || (state?.gen === head.gen && state.digest !== prior?.digest)) {
      chain.push(signed)
    }
  }
  return { chain, events: appliedCopies(held) }
}
