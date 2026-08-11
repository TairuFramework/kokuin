import type { SignedEvent } from './events.js'
import { type FoldOptions, type FoldResult, foldLog, foldLogAsync, type KeyState } from './fold.js'

/**
 * Take the state after a log's last event, turning a fold failure into a throw.
 *
 * The identity (which derives its signing key from that state) and the resolver (which answers
 * with the keys it publishes) both need the same three steps — fold, reject a log that does not
 * fold, take the last state — in both a sync and an async flavour. Factored here so that is one
 * sequence rather than four copies of it.
 *
 * `context` names the caller so its diagnostics survive the factoring.
 */
function foldedStates(did: string, context: string, result: FoldResult): Array<KeyState> {
  if (!result.ok) {
    throw new Error(`${context}: invalid log for ${did}: ${result.reason} at event ${result.index}`)
  }
  return result.states
}

function lastState(did: string, context: string, result: FoldResult): KeyState {
  const states = foldedStates(did, context, result)
  return states[states.length - 1]
}

/**
 * Current state via the synchronous {@link foldLog}. A capability-authorised revoke fails closed
 * here — see {@link currentStateAsync}.
 */
export function currentState(did: string, events: Array<SignedEvent>, context: string): KeyState {
  return lastState(did, context, foldLog(did, events))
}

/**
 * Every per-position state, via {@link foldLogAsync}.
 *
 * What the resolver needs and the identity does not: the identity signs with the key the head
 * establishes, while a verifier has to answer about keys the log has since rotated away — a token
 * outlives the state that gave its `kid` meaning, and a routine rotation must not invalidate every
 * grant the profile has ever made.
 */
export async function allStatesAsync(
  did: string,
  events: Array<SignedEvent>,
  context: string,
  options?: FoldOptions,
): Promise<Array<KeyState>> {
  return foldedStates(did, context, await foldLogAsync(did, events, options))
}

/**
 * Current state via {@link foldLogAsync}, which can await `options.verifyCapability` for a
 * capability-authorised revoke instead of failing closed on it.
 */
export async function currentStateAsync(
  did: string,
  events: Array<SignedEvent>,
  context: string,
  options?: FoldOptions,
): Promise<KeyState> {
  return lastState(did, context, await foldLogAsync(did, events, options))
}
