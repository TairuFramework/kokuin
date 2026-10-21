import { digestOf, isCanonicalizable } from './canonical.js'
import type { EpochLimits } from './epoch.js'
import type { SignedEvent } from './events.js'
import { type FoldResult, foldLog, type KeyState } from './fold.js'
import { MAX_LOG_EVENTS } from './limits.js'
import {
  appliedCopies,
  type ControllerLog,
  isControllerLog,
  LOG_FORKED,
  LOG_NOT_AUTHORITATIVE,
  LOG_TOO_LARGE,
  MALFORMED_LOG,
  withEpoch,
} from './log.js'
import { resolveBranches } from './supersede.js'

export { LOG_FORKED, LOG_NOT_AUTHORITATIVE }

/**
 * Where a consumer keeps the log it has accepted for a DID, so the next presentation can be compared
 * against it and merged into it.
 *
 * A folded log carries no proof it is the *whole* log. A peer serving a prefix of the chain —
 * stopping just before the settlement denying their device — or a full chain with the epoch event
 * that denies it withheld, produces one that folds cleanly and yields a deny set missing exactly the
 * entry that matters. Nothing inside a single log distinguishes that from a log that is simply short.
 * Comparing against what this party has already seen supplies the missing half — a local guarantee,
 * not a global one (it does nothing on a first encounter), but the difference between a suppression
 * attack that works once and one that works every time. The two halves are kept differently because
 * they fold differently: a newer chain replaces the one seen only through the branch rules, and the
 * current epoch's events are never forgotten, only added to.
 *
 * Deliberately not a high-water mark over `(gen, seq)`. A reset legitimately replaces a longer
 * lower-generation chain, which a "never go backwards" mark would reject, bricking the profile as it
 * is recovered. A chain divergence is settled by {@link resolveBranches} instead.
 */
export type LogStore = {
  /** The accepted log for this DID, or undefined when none has been seen. */
  get(did: string): Promise<ControllerLog | undefined>
  /**
   * Replace the log for this DID with what `update` makes of the current one, and return it. Atomic
   * per DID: no two `update`s for one DID interleave, so two presentations merged concurrently both
   * land rather than the second overwriting the first with a log built from a stale read. When
   * `update` throws, nothing is written and the throw propagates. `update` may be invoked more than
   * once (a persistent store reruns it when it loses a first-insert race), so it must be free of side
   * effects; only the last result is written. An `update` returning `current` itself (the very object
   * it was handed) means nothing changed, and the store skips the write: `authoritativeLog` answers
   * that way whenever a resolution learned nothing new, which is most of them.
   */
  merge(
    did: string,
    update: (current: ControllerLog | undefined) => Promise<ControllerLog>,
  ): Promise<ControllerLog>
}

/**
 * An in-memory {@link LogStore}. Enough for a process that resolves the same DIDs repeatedly, and for
 * tests; a consumer that survives restarts wants a persistent one, since the guarantee is only as
 * durable as the memory of what was seen.
 *
 * `merge` is serialised per DID by a promise chain: each update starts only after the previous one for
 * that DID settled, failed or not. A failed update must not wedge the chain, so the link kept is one
 * that never rejects; the caller still sees the failure on the promise `merge` returned.
 */
export function createMemoryLogStore(): LogStore {
  const logs = new Map<string, ControllerLog>()
  const tails = new Map<string, Promise<void>>()
  return {
    async get(did: string): Promise<ControllerLog | undefined> {
      return logs.get(did)
    },
    merge(
      did: string,
      update: (current: ControllerLog | undefined) => Promise<ControllerLog>,
    ): Promise<ControllerLog> {
      const previous = tails.get(did) ?? Promise.resolve()
      const run = previous.then(async () => {
        const current = logs.get(did)
        const next = await update(current)
        if (next !== current) logs.set(did, next)
        return next
      })
      const tail = run.then(
        () => undefined,
        () => undefined,
      )
      tails.set(did, tail)
      // Drop the link once nothing is queued behind it, so the map holds only DIDs mid-merge.
      void tail.then(() => {
        if (tails.get(did) === tail) {
          tails.delete(did)
        }
      })
      return run
    },
  }
}

/** The stored log and its chain's fold, or undefined when there is no usable memory. */
function recall(
  did: string,
  seen: ControllerLog | undefined,
): { log: ControllerLog; head: KeyState } | undefined {
  if (seen == null || !isControllerLog(seen) || seen.chain.length === 0) {
    return undefined
  }
  const folded = foldLog(did, { chain: seen.chain, events: [] })
  const head = folded.ok ? folded.states[folded.states.length - 1] : undefined
  return head === undefined ? undefined : { log: seen, head }
}

/** A chain or epoch entry, as far as comparing two of them needs. */
type Entry = Pick<SignedEvent, 'sigs' | 'recoveryKey'> & { event: unknown }

/** One log entry and another hold the same bytes: the same body, signatures and recovery key. */
function sameEntry(entry: Entry, other: unknown): boolean {
  if (other == null || typeof other !== 'object') return false
  const { event, sigs, recoveryKey } = other as Partial<SignedEvent>
  if (recoveryKey !== entry.recoveryKey || !Array.isArray(sigs)) return false
  if (sigs.length !== entry.sigs.length || sigs.some((sig, i) => sig !== entry.sigs[i])) {
    return false
  }
  // Digests, not object identity or JSON text: a store hands back a fresh copy, possibly with its
  // keys reordered (Postgres `jsonb`), and the canonical form is what both sides agree on.
  return isCanonicalizable(event) && digestOf(event) === digestOf(entry.event)
}

/** Whether `next` is `seen` again, entry for entry, so remembering it would change nothing. */
function sameLog(next: ControllerLog, seen: ControllerLog): boolean {
  const pairs: Array<[Array<Entry>, Array<unknown>]> = [
    [next.chain, seen.chain],
    [next.events, seen.events],
  ]
  return pairs.every(
    ([mine, theirs]) =>
      mine.length === theirs.length && mine.every((entry, i) => sameEntry(entry, theirs[i])),
  )
}

/** What {@link authoritativeLog} takes. */
export type AuthoritativeLogParams = {
  did: string
  loaded: ControllerLog
  seen: ControllerLog | undefined
  context: string
}

/**
 * What {@link authoritativeLog} answers: the log to remember, and the fold to answer from. `log` is
 * `seen` itself, the same object, when the resolution learned nothing new; see `LogStore.merge`.
 */
export type AuthoritativeLog = { log: ControllerLog; result: Extract<FoldResult, { ok: true }> }

/**
 * Fold the loaded log against the one already seen, and say what to remember.
 *
 * **The chain** is settled exactly as before epochs existed. The loaded chain must extend (or be) the
 * one seen — its fold passes through the seen head — or win against it under
 * {@link resolveBranches}; a chain that loses is refused ({@link LOG_NOT_AUTHORITATIVE}: truncation),
 * and a fork is refused outright ({@link LOG_FORKED}: answering from either side is a guess). The
 * comparison is on folded head digests, never array identity — the same history re-loaded is a
 * different array, and identity would reject the commonest call there is. These are throws because a
 * resolver has no other way to say "I will not answer for this DID".
 *
 * **The epoch** is the union of what was seen and what was loaded, folded on the settled chain: a
 * presentation that withholds an event this party has seen cannot make it forget it. The returned
 * `result` answers for that union, not for the presentation alone.
 *
 * **What to remember** is the settled chain and the current epoch's applied events — nothing else.
 * From `loaded`, an unsigned, forged, malformed or still-pending entry was never authenticated, so it
 * never reaches the store: a relay flooding a presentation changes nothing remembered (and, counting
 * only applied events, cannot saturate the epoch either). A pending event is not lost forever by
 * this, only not vouched for: once its parents are known, presenting it again applies it. Events of
 * any other epoch are dropped, seen or not: an event naming another epoch has no effect, its effect is
 * in the newer snapshot or was dropped by it, and a verifier never needs to ingest a superseded epoch
 * to fold the current one. That is what bounds memory: one epoch, at most `MAX_EPOCH_EVENTS + 1`
 * events once saturated (see `appliedCopies`), so a held log always passes the request limit when
 * forwarded, and a flooded epoch is gone the moment a settlement supersedes it. A saturated epoch's
 * refusal persists through a later presentation of a subset, until that settlement.
 *
 * A stored log whose chain no longer folds is treated as no memory: local corruption or a tightened
 * fold rule is one round of the guarantee to give up, since only a folded log was ever stored and
 * refusing forever would brick every cached profile. A stored *saturated* epoch is not that case — it
 * folds, saturated, and is merged like any other memory, so its refusal stands. Stored epoch events are
 * folded together with the presentation without the request limit, which bounds a single input, not
 * the union of two inputs that each passed it.
 *
 * **What is checked.** Stored epoch events of the settled chain's current epoch are not
 * authenticated again: they were when they were stored, and a copy that verified under an epoch
 * verifies under it every time (see `FoldEpochParams.trusted`). They are still authorised afresh,
 * and a stored event of another epoch is simply ignored. Only what `loaded` adds is checked, and
 * `loaded` is refused as a whole, memory untouched, once more than `MAX_FAILED_SIGNATURES` of its
 * signatures fail (`TOO_MANY_FAILED_SIGNATURES`). This trusts the store: one that an attacker
 * can write to defeats every guarantee here anyway, since it can simply forget what was seen.
 */
export function authoritativeLog(params: AuthoritativeLogParams): AuthoritativeLog {
  return authoritativeLogWithin(params)
}

/**
 * {@link authoritativeLog} under lowered epoch limits. Test-only: saturation is then reachable
 * without thousands of signatures. Not exported from the package.
 */
export function authoritativeLogWithin(
  { did, loaded, seen, context }: AuthoritativeLogParams,
  limits?: Partial<EpochLimits>,
): AuthoritativeLog {
  const invalid = (reason: string, index: number) =>
    new Error(`${context}: invalid log for ${did}: ${reason} at event ${index}`)
  // The request limit, before any work: `loaded` is the one untrusted input here.
  if (!isControllerLog(loaded)) {
    throw invalid(MALFORMED_LOG, 0)
  }
  if (loaded.events.length > MAX_LOG_EVENTS) {
    throw invalid(LOG_TOO_LARGE, -1)
  }
  const loadedChain = foldLog(did, { chain: loaded.chain, events: [] })
  if (!loadedChain.ok) {
    throw invalid(loadedChain.reason, loadedChain.index)
  }
  const loadedHead = loadedChain.states[loadedChain.states.length - 1]
  if (loadedHead === undefined) {
    throw invalid('no state produced', 0)
  }

  let chain = loaded.chain
  let states = loadedChain.states
  const memory = recall(did, seen)
  if (memory !== undefined && !states.some((state) => state.digest === memory.head.digest)) {
    // They diverge. Which is authoritative is what branch resolution answers: a higher generation (a
    // reset) wins outright, a chain that only repeats the seen one's prefix loses, and two rotates at
    // one position are a fork.
    const resolved = resolveBranches(did, [memory.log.chain, loaded.chain])
    if (!resolved.ok) {
      throw new Error(
        `${resolved.failure === 'duplicity' ? LOG_FORKED : LOG_NOT_AUTHORITATIVE}: ${did}`,
      )
    }
    const winner = foldLog(did, { chain: resolved.winner, events: [] })
    const winnerHead = winner.ok ? winner.states[winner.states.length - 1] : undefined
    if (!winner.ok || winnerHead === undefined || winnerHead.digest !== loadedHead.digest) {
      throw new Error(`${LOG_NOT_AUTHORITATIVE}: ${did}`)
    }
    chain = resolved.winner
    states = winner.states
  }

  const held = withEpoch(did, states, loaded.events, limits, memory?.log.events)
  if (!('result' in held)) {
    throw invalid(held.reason, held.index)
  }
  const log = { chain, events: appliedCopies(held, limits) }
  return {
    log: memory !== undefined && sameLog(log, memory.log) ? memory.log : log,
    result: held.result,
  }
}
