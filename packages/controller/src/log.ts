import type { EpochEvent } from './epoch-events.js'
import type { SignedEvent } from './events.js'

/**
 * Everything a controller's log holds: the root chain, which fixes the keys and every settlement, and
 * the epoch events that built up on the chain's last event since. They are separate lists because
 * they fold by different rules -- the chain is a sequence, order is meaning; the epoch is a set,
 * order is nothing -- and a presentation of one is no claim about the other.
 */
export type ControllerLog = { chain: Array<SignedEvent>; events: Array<SignedEvent<EpochEvent>> }

/** What a request carrying more epoch events than {@link MAX_LOG_EVENTS} fails with. */
export const LOG_TOO_LARGE = 'controller log exceeds request limits'

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
