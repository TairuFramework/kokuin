import type { SignedEvent } from './events.js'
import { type FoldOptions, type FoldResult, foldLog, foldLogAsync, type KeyState } from './fold.js'

/**
 * Fold results to states, turning a fold failure into a throw. The identity and the resolver both
 * need the same fold-reject-take-last sequence, sync and async, so it lives here once. `context`
 * names the caller so its diagnostics survive the factoring.
 */
function foldedStates(did: string, context: string, result: FoldResult): Array<KeyState> {
  if (!result.ok) {
    throw new Error(`${context}: invalid log for ${did}: ${result.reason} at event ${result.index}`)
  }
  return result.states
}

function lastState(did: string, context: string, result: FoldResult): KeyState {
  const states = foldedStates(did, context, result)
  const last = states[states.length - 1]
  if (last === undefined) {
    throw new Error(`${context}: no state produced for ${did}`)
  }
  return last
}

/**
 * Current state via the synchronous {@link foldLog}. A capability-authorised revoke fails closed
 * here — see {@link currentStateAsync}.
 */
export function currentState(did: string, events: Array<SignedEvent>, context: string): KeyState {
  return lastState(did, context, foldLog(did, events))
}

/**
 * Every per-position state, via {@link foldLogAsync}. What the resolver needs and the identity does
 * not: a verifier has to answer about keys the log has since rotated away, since a token outlives the
 * state that gave its `kid` meaning.
 */
export async function allStatesAsync({
  did,
  events,
  context,
  options,
}: {
  did: string
  events: Array<SignedEvent>
  context: string
  options?: FoldOptions
}): Promise<Array<KeyState>> {
  return foldedStates(did, context, await foldLogAsync(did, events, options))
}

/**
 * Current state via {@link foldLogAsync}, which can await `options.verifyCapability` for a
 * capability-authorised revoke instead of failing closed on it.
 */
export async function currentStateAsync({
  did,
  events,
  context,
  options,
}: {
  did: string
  events: Array<SignedEvent>
  context: string
  options?: FoldOptions
}): Promise<KeyState> {
  return lastState(did, context, await foldLogAsync(did, events, options))
}
