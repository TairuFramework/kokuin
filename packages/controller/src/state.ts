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
function lastState(did: string, context: string, result: FoldResult): KeyState {
  if (!result.ok) {
    throw new Error(`${context}: invalid log for ${did}: ${result.reason} at event ${result.index}`)
  }
  return result.states[result.states.length - 1]
}

/**
 * Current state via the synchronous {@link foldLog}. A capability-authorised revoke fails closed
 * here — see {@link currentStateAsync}.
 */
export function currentState(did: string, events: Array<SignedEvent>, context: string): KeyState {
  return lastState(did, context, foldLog(did, events))
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
