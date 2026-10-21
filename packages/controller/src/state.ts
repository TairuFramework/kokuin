import type { SignedEvent } from './events.js'
import { type FoldResult, foldLog, type KeyState } from './fold.js'

/**
 * Fold results to states, turning a fold failure into a throw. The identity and the resolver both
 * need the same fold-reject-take-last sequence, so it lives here once. `context`
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

/** Current state of a log. */
export function currentState(did: string, events: Array<SignedEvent>, context: string): KeyState {
  return lastState(did, context, foldLog(did, { chain: events, events: [] }))
}

/**
 * Every per-position state. What the resolver needs and the identity does not: a verifier has to
 * answer about keys the log has since rotated away, since a token outlives the state that gave its
 * `kid` meaning.
 */
export function allStates(
  did: string,
  events: Array<SignedEvent>,
  context: string,
): Array<KeyState> {
  return foldedStates(did, context, foldLog(did, { chain: events, events: [] }))
}
