import { digestOf } from './canonical.js'
import {
  type AuthoritativeLog,
  type AuthoritativeLogParams,
  authoritativeLogWithin,
} from './history.js'
import { type ControllerLog, isControllerLog } from './log.js'

/** How many settled folds {@link memoizedAuthoritativeLog} keeps, least recently used evicted first. */
export const FOLD_MEMO_SIZE = 256

/**
 * A remembered fold: its answer, and whether it was "nothing new" — `log` was the `seen` it was handed.
 * That second half cannot be kept as the object: the `seen` of a later hit is a different object with
 * the same content, and it is that object `LogStore.merge` must get back to skip its write.
 */
type MemoEntry = { log: ControllerLog; unchanged: boolean; result: AuthoritativeLog['result'] }

// Module-level, not per resolver: a consumer that builds a resolver per resolution (kubun's engine
// does) would otherwise never hit. Sharing is sound because the key is the whole input of a pure
// function — see `memoKey` — so two resolvers can only share an entry when they would compute the
// same answer.
const memo = new Map<string, MemoEntry>()

/** Whether a log entry is shaped like a signed event and carries no capability authorisation. */
function memoizableEntry(entry: unknown): boolean {
  if (entry == null || typeof entry !== 'object') return false
  const { event } = entry as { event?: unknown }
  if (event == null || typeof event !== 'object') return false
  // A capability-authorised event is verified against the clock: its fold is a function of the time
  // as well as of the log, so the same bytes may not fold the same way twice. This version of the
  // fold has no such event, but a log carrying a `cap` must never be answered from memory.
  return !Object.hasOwn(event, 'cap')
}

function memoizableLog(log: unknown): log is ControllerLog {
  return (
    isControllerLog(log) && log.chain.every(memoizableEntry) && log.events.every(memoizableEntry)
  )
}

/**
 * The memo key: every input of the fold, or undefined when the inputs are not memoizable.
 *
 * `authoritativeLogWithin` reads nothing but its arguments — no clock, no callback, no store — so its
 * answer is a function of the DID, the exact loaded log, the exact seen log and the epoch limits. The
 * logs are keyed by canonical digest: any new event (a revoke) changes the digest and forces a fold,
 * and so does any difference in what was seen. Only the default limits are memoized; lowered limits
 * are a test-only path.
 */
function memoKey(
  { did, loaded, seen }: AuthoritativeLogParams,
  limits: object | undefined,
): string | undefined {
  if (limits !== undefined) return undefined
  if (!memoizableLog(loaded)) return undefined
  if (seen !== undefined && !memoizableLog(seen)) return undefined
  try {
    return JSON.stringify([did, digestOf(loaded), seen === undefined ? null : digestOf(seen)])
  } catch {
    // Not canonicalizable (non-finite number, too deep): the fold refuses it, and nothing is kept.
    return undefined
  }
}

/**
 * {@link authoritativeLogWithin}, answered from a bounded, process-wide memo when the exact same
 * inputs were folded before. The fold verifies every signature of the log, every time; on a phone
 * syncing documents from one controller that is most of the CPU, for a log that has not changed.
 *
 * Only successes are remembered: a refusal (truncation, fork, a malformed log) is recomputed on every
 * call, and so throws again. The anti-truncation check is not bypassed because `seen` is part of the
 * key: a prefix memoized before anything was seen is a different entry from the same prefix
 * presented against the longer log accepted since, and that one is folded — and refused.
 */
export function memoizedAuthoritativeLog(
  params: AuthoritativeLogParams,
  limits?: Parameters<typeof authoritativeLogWithin>[1],
): AuthoritativeLog {
  const key = memoKey(params, limits)
  if (key === undefined) {
    return authoritativeLogWithin(params, limits)
  }
  const known = memo.get(key)
  if (known !== undefined) {
    // Refreshed, so the least recently *used* entry is the one evicted.
    memo.delete(key)
    memo.set(key, known)
    const { seen } = params
    return { log: known.unchanged && seen !== undefined ? seen : known.log, result: known.result }
  }
  const settled = authoritativeLogWithin(params, limits)
  memo.set(key, {
    log: settled.log,
    unchanged: settled.log === params.seen,
    result: settled.result,
  })
  if (memo.size > FOLD_MEMO_SIZE) {
    const oldest = memo.keys().next().value
    if (oldest !== undefined) memo.delete(oldest)
  }
  return settled
}

/** Forget every memoized fold. Test-only; not exported from the package. */
export function clearFoldMemo(): void {
  memo.clear()
}
