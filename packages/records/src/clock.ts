import { HLC, type HLCTimestamp } from '@sozai/hlc'

/**
 * The serialized counter is eight zero-padded digits, so that string order matches numeric
 * order. A larger counter still round-trips — `padStart` never truncates — but its ninth
 * digit would sort it below a smaller one.
 */
const COUNTER_CEILING = 1e8

/**
 * Parse a stamp only if it is spelled exactly as `HLC.serialize` spells it, or answer `null`.
 *
 * `HLC.tryParse` checks that each field is finite, not that the string is the one those fields
 * serialize to: an unpadded counter, a missing millisecond part or a day past the month end
 * all parse. Such a stamp orders by its parsed fields but stores and syncs by its bytes, so it
 * would sort one way in a comparison and another way in a range. Only the round trip rules
 * that out.
 *
 * `tryParse` has to run first: serializing a non-finite wall time throws.
 */
export function parseCanonicalHLC(hlc: string): HLCTimestamp | null {
  const parsed = HLC.tryParse(hlc)
  if (parsed === null || parsed.counter >= COUNTER_CEILING) {
    return null
  }
  return HLC.serialize(parsed) === hlc ? parsed : null
}

/** Order signed decision stamps by the complete HLC, including the node ID. */
export function compareRecordDecisionHLC(left: string, right: string): number {
  const leftStamp = parseCanonicalHLC(left)
  const rightStamp = parseCanonicalHLC(right)
  if (leftStamp === null || rightStamp === null)
    throw new Error('Record decision HLC must be canonical')
  return HLC.compare(leftStamp, rightStamp)
}

/**
 * Parse a stamp that arrived from a peer, or answer `null`: it must be canonical and no
 * further than `maxDriftMS` ahead of `nowMS`. The past is unbounded, since an offline write
 * lands late.
 *
 * This has to gate a stamp before anything reads it, the local clock included: a far-future
 * stamp that landed would sort above every later local write and freeze the record. A
 * negative or non-numeric drift limit, or a non-finite `nowMS`, rejects every stamp — every
 * comparison against `NaN` is false, so an unchecked one would admit any future.
 */
export function parseBoundedHLC(
  hlc: string,
  nowMS: number,
  maxDriftMS: number,
): HLCTimestamp | null {
  if (!Number.isFinite(nowMS) || !(maxDriftMS >= 0)) {
    return null
  }
  const parsed = parseCanonicalHLC(hlc)
  if (parsed === null || parsed.wallTime - nowMS > maxDriftMS) {
    return null
  }
  return parsed
}
