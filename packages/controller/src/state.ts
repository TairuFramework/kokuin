import { type FoldResult, foldLog, type KeyState } from './fold.js'
import { type ControllerLog, isControllerLog, MALFORMED_LOG } from './log.js'

/** The fold's last state, turning a fold failure into a throw. `context` names the caller. */
function lastState(did: string, context: string, result: FoldResult): KeyState {
  if (!result.ok) {
    throw new Error(`${context}: invalid log for ${did}: ${result.reason} at event ${result.index}`)
  }
  const last = result.states[result.states.length - 1]
  if (last === undefined) {
    throw new Error(`${context}: no state produced for ${did}`)
  }
  return last
}

/**
 * The root key state a log establishes: the chain's last state.
 *
 * The chain alone, deliberately. Epoch events never change a root key (`k`, `ka`, `n` and the
 * derivation indices live on the chain only), so folding them would buy an identity nothing but up
 * to `MAX_EPOCH_EVENTS` signature checks on a path that must stay synchronous and cheap. The returned
 * state's `deny`, `members` and `saturated` are therefore the chain's, not the live ones; nothing
 * that builds an identity reads them.
 */
export function currentState(did: string, log: ControllerLog, context: string): KeyState {
  if (!isControllerLog(log)) {
    throw new Error(`${context}: invalid log for ${did}: ${MALFORMED_LOG} at event 0`)
  }
  return lastState(did, context, foldLog(did, { chain: log.chain, events: [] }))
}
