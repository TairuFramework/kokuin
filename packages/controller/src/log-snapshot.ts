import { digestOf, isCanonicalizable } from './canonical.js'
import { type ControllerLog, isControllerLog } from './log.js'

/** Own canonical bodies before verification suspends; malformed entries still reach refusal guards. */
export function snapshotEntries(entries: Array<unknown>): Array<unknown> {
  return entries.map((entry) => {
    if (entry === null || typeof entry !== 'object') return entry
    const { event, sigs, recoveryKey } = entry as Record<string, unknown>
    return {
      event: isCanonicalizable(event) ? structuredClone(event) : undefined,
      sigs: Array.isArray(sigs) ? [...sigs] : sigs,
      recoveryKey,
    }
  })
}

export function snapshotLog(log: ControllerLog): ControllerLog {
  if (!isControllerLog(log)) return log
  return {
    chain: snapshotEntries(log.chain) as ControllerLog['chain'],
    events: snapshotEntries(log.events) as ControllerLog['events'],
  }
}

/** Retain unchanged caller objects only while they still describe the authenticated snapshot. */
export function unchangedEntries(owned: Array<unknown>, original: Array<unknown>): boolean {
  if (!Array.isArray(original) || original.length !== owned.length) return false
  return owned.every((value, index) => {
    const other = original[index]
    if (value === null || typeof value !== 'object' || other === null || typeof other !== 'object')
      return false
    const entry = value as Record<string, unknown>
    const candidate = other as Record<string, unknown>
    return (
      entry.recoveryKey === candidate.recoveryKey &&
      Array.isArray(entry.sigs) &&
      Array.isArray(candidate.sigs) &&
      entry.sigs.length === candidate.sigs.length &&
      entry.sigs.every((sig, i) => sig === (candidate.sigs as Array<unknown>)[i]) &&
      isCanonicalizable(candidate.event) &&
      digestOf(entry.event) === digestOf(candidate.event)
    )
  })
}
