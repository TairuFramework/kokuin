import type { SignedEvent } from './events.js'
import { type FoldOptions, foldLogAsync, type KeyState } from './fold.js'
import { allStatesAsync } from './state.js'
import { needsCapabilityVerification, resolveBranchesAsync } from './supersede.js'

/**
 * Where a consumer keeps the last log it accepted for a DID, so the next one can be compared against
 * it.
 *
 * A folded log carries no proof it is the *whole* log: a peer serving a prefix — stopping just before
 * the `rev` denying their device — produces one that folds cleanly and yields a deny set missing
 * exactly the entry that matters. Nothing inside a single log distinguishes truncation from a log
 * that is simply short, so the fork-detection limitation does not reach it: there is no second branch,
 * only an honest-looking prefix. Comparing against what this party has already seen supplies the
 * missing second branch — a local guarantee, not a global one (it does nothing on a first encounter),
 * but the difference between a suppression attack that works once and one that works every time.
 *
 * Deliberately not a high-water mark over `(gen, seq)`. Supersession legitimately *lowers* the
 * sequence: a thief's long current-key branch is beaten by the owner's recovering rotate at a much
 * lower `seq`, which a "never go backwards" mark would reject, bricking the profile as it is rescued.
 * A divergence is settled by {@link resolveBranchesAsync} instead.
 */
export type LogStore = {
  /** The last accepted log for this DID, or undefined when none has been seen. */
  get(did: string): Promise<Array<SignedEvent> | undefined>
  /** Record a log as the last accepted one. Called only after it has folded. */
  set(did: string, log: Array<SignedEvent>): Promise<void>
}

/** What a resolver answers with when the log it loaded loses to the one already seen. */
export const LOG_NOT_AUTHORITATIVE = 'the loaded log does not supersede the one already seen'

/** What a resolver answers with when the loaded log and the one already seen are a genuine fork. */
export const LOG_FORKED = 'the loaded log and the one already seen are a fork'

/**
 * An in-memory {@link LogStore}. Enough for a process that resolves the same DIDs repeatedly, and for
 * tests; a consumer that survives restarts wants a persistent one, since the guarantee is only as
 * durable as the memory of what was seen.
 */
export function createMemoryLogStore(): LogStore {
  const logs = new Map<string, Array<SignedEvent>>()
  return {
    async get(did: string): Promise<Array<SignedEvent> | undefined> {
      return logs.get(did)
    },
    async set(did: string, log: Array<SignedEvent>): Promise<void> {
      logs.set(did, log)
    },
  }
}

/**
 * Fold the loaded log, having established that it is not behind one this party has already seen.
 *
 * The two rejections are throws because a resolver has no other way to say "I will not answer for this
 * DID", and answering from the loser is the failure this prevents: a prefix loses to the log it is a
 * prefix of (truncation refused), and a fork is refused outright (resolving to either side is a
 * guess). The comparison is on the **folded head digest**, never array identity — the same history
 * re-loaded is a different array, and identity would reject the commonest call there is.
 *
 * A stored log that no longer folds is treated as no memory, but only when it *genuinely* no longer
 * folds: local corruption or a tightened fold rule is one round of the guarantee to give up, since
 * only a folded log was ever stored and refusing forever would brick every cached profile. A stored
 * log that fails only because this call has no `verifyCapability` for a cap-authorised revoke it
 * carries is the opposite — nothing changed, the call is simply not equipped — so it fails closed;
 * treating it as no memory would disable the truncation guard for management-tier profiles.
 *
 * The states are returned so the caller does not fold twice; the log travels with them for the store.
 */
export async function authoritativeStates({
  did,
  loaded,
  seen,
  context,
  options,
}: {
  did: string
  loaded: Array<SignedEvent>
  seen: Array<SignedEvent> | undefined
  context: string
  options: FoldOptions
}): Promise<{ log: Array<SignedEvent>; states: Array<KeyState> }> {
  const states = await allStatesAsync({ did, events: loaded, context, options: options })
  if (seen == null || seen.length === 0) {
    return { log: loaded, states }
  }
  const previous = await foldLogAsync(did, seen, options)
  if (!previous.ok) {
    // "Fold rule tightened" is safe to treat as no memory (only a folded log was stored, so refusing
    // forever would brick every cached profile). "I remember a management-tier log and got no verifier
    // for it" is not: accepting the loaded log there disables the truncation guard for exactly those
    // profiles, letting an attacker's prefix that stops before the cap-authorised `rev` be accepted
    // because the fuller stored log is the one that could not be folded. Fail closed — what could not
    // be checked is not evidence its target is absent.
    if (needsCapabilityVerification(previous)) {
      throw new Error(`${LOG_NOT_AUTHORITATIVE}: ${did}`)
    }
    return { log: loaded, states }
  }

  const headState = states[states.length - 1]
  const previousHeadState = previous.states[previous.states.length - 1]
  if (headState === undefined || previousHeadState === undefined) {
    throw new Error(`${LOG_NOT_AUTHORITATIVE}: ${did}`)
  }
  const head = headState.digest
  // The loaded log extends, or is, the history seen: its fold passed through that head. Ordinary path.
  if (states.some((state) => state.digest === previousHeadState.digest)) {
    return { log: loaded, states }
  }

  // They diverge. Which is authoritative is what branch resolution answers, and the only thing that
  // knows a superseding rotate outranks a longer branch of current-key events.
  const resolved = await resolveBranchesAsync(did, [seen, loaded], options)
  if (!resolved.ok) {
    throw new Error(
      `${resolved.failure === 'duplicity' ? LOG_FORKED : LOG_NOT_AUTHORITATIVE}: ${did}`,
    )
  }
  // A comparison that did not happen is a refusal, not a pass: `unverified` means one side could not
  // be folded for want of a verifier. Always zero with one configured.
  if (resolved.unverified > 0) {
    throw new Error(`${LOG_NOT_AUTHORITATIVE}: ${did}`)
  }
  const winner = await foldLogAsync(did, resolved.winner, options)
  const winnerHead = winner.ok ? winner.states[winner.states.length - 1] : undefined
  if (winnerHead === undefined || winnerHead.digest !== head) {
    throw new Error(`${LOG_NOT_AUTHORITATIVE}: ${did}`)
  }
  return { log: loaded, states }
}
