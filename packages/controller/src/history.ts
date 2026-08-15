import type { SignedEvent } from './events.js'
import { type FoldOptions, foldLogAsync, type KeyState } from './fold.js'
import { allStatesAsync } from './state.js'
import { needsCapabilityVerification, resolveBranchesAsync } from './supersede.js'

/**
 * Where a consumer keeps the last log it accepted for a DID, so the next one can be compared
 * against it.
 *
 * A folded log carries no proof that it is the *whole* log. Every event chains, every signature
 * verifies, and a peer who serves a prefix — stopping just before the `rev` that denies their
 * device — produces one that folds cleanly and yields a deny set missing exactly the entry that
 * matters. Nothing inside a single log distinguishes truncation from a log that is simply short,
 * which is why the named limitation about *forks* does not reach it: there is no second branch to
 * compare, only an honest-looking prefix.
 *
 * Comparing against what this party has already seen is what supplies the missing second branch.
 * That is a local guarantee and not a global one — it does nothing on a first encounter, and only a
 * witness or an anchor can — but it is the difference between a suppression attack that works once
 * and one that works every time, and it costs a store this consumer very likely already keeps.
 *
 * Deliberately not a high-water mark over `(gen, seq)`. Supersession legitimately *lowers* the
 * sequence: a thief holding a current key can append revokes until their branch is long, and the
 * owner's recovering rotate — which supersedes all of it — sits at a much lower `seq`. A mark that
 * refused anything behind the highest seen would reject exactly that recovery and brick the profile
 * at the moment it is being rescued. So a divergence is settled by {@link resolveBranchesAsync},
 * which knows that a rotate signed by the pre-committed keys beats any length of current-key events.
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
 * An in-memory {@link LogStore}. Enough for a process that resolves the same DIDs repeatedly, and
 * for tests; a consumer that survives restarts wants a persistent one, since the guarantee is only
 * as durable as the memory of what was seen.
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
 * Three outcomes, and the two rejections are throws because a resolver has no other way to say "I
 * will not answer for this DID" — and answering from the loser is the failure this exists to
 * prevent. A prefix loses to the log it is a prefix of, which is truncation refused. A fork is
 * refused outright, because resolving to either side of one is a guess.
 *
 * The comparison is on the **folded head digest**, never on array identity: the same history
 * re-loaded is two different arrays, and de-duplication inside branch resolution answers with
 * whichever of them it kept. Identity would therefore reject the commonest call there is — the same
 * unchanged log, loaded again.
 *
 * A stored log that no longer folds is treated as no memory rather than as a refusal — but only when
 * the reason is that it genuinely no longer folds. Local corruption or a fold rule that has since
 * tightened (a package upgrade) is one round of the guarantee to give up, since only a folded log was
 * ever stored and refusing forever would brick every cached profile. A stored log that fails to fold
 * solely because this call has no `verifyCapability` for a capability-authorised revoke it carries is
 * the opposite case: nothing about the remembered log has changed, the call is simply not equipped to
 * check it, and treating that as no memory would disable the truncation guard for management-tier
 * profiles. That case fails closed instead — see the check inside.
 *
 * The states are returned rather than the log alone so the caller does not fold twice; the log
 * travels with them for the store.
 */
export async function authoritativeStates(
  did: string,
  loaded: Array<SignedEvent>,
  seen: Array<SignedEvent> | undefined,
  context: string,
  options: FoldOptions,
): Promise<{ log: Array<SignedEvent>; states: Array<KeyState> }> {
  const states = await allStatesAsync(did, loaded, context, options)
  if (seen == null || seen.length === 0) {
    return { log: loaded, states }
  }
  const previous = await foldLogAsync(did, seen, options)
  if (!previous.ok) {
    // A stored log that fails only because this call cannot check a capability is a different case
    // from one that no longer folds, and the two must not share an answer. "The fold rule tightened"
    // is safe to treat as no memory: only a log that folded was ever stored, so refusing forever
    // would brick every cached profile, and the cost is one round of the guarantee. "I remember a
    // management-tier log and was handed no verifier for it" is not that — it is a call not equipped
    // to check what it remembers, and accepting the loaded log there disables the truncation guard
    // for exactly the profiles that use the management tier: an attacker serving a prefix that stops
    // before the cap-authorised `rev` denying their device folds cleanly with no verifier and is
    // accepted, because the fuller log this party already holds is the one that could not be folded.
    // Fail closed: what could not be checked is not evidence that what it protects against is absent.
    if (needsCapabilityVerification(previous)) {
      throw new Error(`${LOG_NOT_AUTHORITATIVE}: ${did}`)
    }
    return { log: loaded, states }
  }

  const head = states[states.length - 1].digest
  // The loaded log extends, or is, the history already seen: its fold passed through that head. This
  // is the ordinary path — an unchanged log, or one with events appended since.
  if (states.some((state) => state.digest === previous.states[previous.states.length - 1].digest)) {
    return { log: loaded, states }
  }

  // They diverge. Which is authoritative is exactly the question branch resolution answers, and it
  // is the only thing that knows a superseding rotate outranks a longer branch of current-key
  // events — the recovery case a naive "never go backwards" rule would reject.
  const resolved = await resolveBranchesAsync(did, [seen, loaded], options)
  if (!resolved.ok) {
    throw new Error(
      `${resolved.failure === 'duplicity' ? LOG_FORKED : LOG_NOT_AUTHORITATIVE}: ${did}`,
    )
  }
  // A comparison that did not happen is a refusal, not a pass: `unverified` means one of the two
  // could not be folded for want of a capability verifier. With one configured it is always zero.
  if (resolved.unverified > 0) {
    throw new Error(`${LOG_NOT_AUTHORITATIVE}: ${did}`)
  }
  const winner = await foldLogAsync(did, resolved.winner, options)
  if (!winner.ok || winner.states[winner.states.length - 1].digest !== head) {
    throw new Error(`${LOG_NOT_AUTHORITATIVE}: ${did}`)
  }
  return { log: loaded, states }
}
