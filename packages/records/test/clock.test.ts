import { HLC } from '@sozai/hlc'
import { describe, expect, test } from 'vitest'

import { compareRecordDecisionHLC, parseBoundedHLC } from '../src/index.js'

const NOW = Date.parse('2026-09-26T12:00:00.000Z')
const DRIFT = 60_000

function stamp(wallTime: number, counter = 0, nodeID = 'node-a'): string {
  return HLC.serialize({ wallTime, counter, nodeID })
}

test('decision comparison refuses a non-canonical HLC instead of ordering its text', () => {
  const loose = '2026-09-26T12:00:00.000Z:1:z'
  const canonical = stamp(NOW, 2, 'a')
  expect(HLC.tryParse(loose)).not.toBeNull()
  expect(() => compareRecordDecisionHLC(loose, canonical)).toThrow()
  expect(compareRecordDecisionHLC(stamp(NOW, 10), stamp(NOW, 2))).toBeGreaterThan(0)
})

describe('parseBoundedHLC', () => {
  test('a stamp as HLC.serialize spells it parses to the same timestamp', () => {
    const ts = { wallTime: NOW - 5, counter: 42, nodeID: 'did:key:z6Mk:node' }
    expect(parseBoundedHLC(HLC.serialize(ts), NOW, DRIFT)).toEqual(ts)
  })

  test('an old but valid stamp is accepted: the past is unbounded', () => {
    const ts = { wallTime: 0, counter: 0, nodeID: 'node-a' }
    expect(parseBoundedHLC(HLC.serialize(ts), NOW, DRIFT)).toEqual(ts)
  })

  test('a stamp exactly at the drift bound is accepted, one millisecond past it is not', () => {
    expect(parseBoundedHLC(stamp(NOW + DRIFT), NOW, DRIFT)).not.toBeNull()
    expect(parseBoundedHLC(stamp(NOW + DRIFT + 1), NOW, DRIFT)).toBeNull()
  })

  test.each([
    ['counter with missing padding', '2026-09-26T12:00:00.000Z:1:node-a'],
    ['counter with trailing garbage', '2026-09-26T12:00:00.000Z:00000001x:node-a'],
    ['counter with a sign', '2026-09-26T12:00:00.000Z:+0000001:node-a'],
    ['negative counter', '2026-09-26T12:00:00.000Z:-0000001:node-a'],
    ['counter past the pad width', '2026-09-26T12:00:00.000Z:100000000:node-a'],
    ['wall time without milliseconds', '2026-09-26T12:00:00Z:00000000:node-a'],
    ['wall time with a short year form', '+002026-09-26T12:00:00.000Z:00000000:node-a'],
    ['leading whitespace', ' 2026-09-26T12:00:00.000Z:00000000:node-a'],
    ['no Z designator', '2026-09-26T12:00:00.000+00:00:00000000:node-a'],
    ['invalid date', '2026-13-01T12:00:00.000Z:00000000:node-a'],
    ['day past the month end, which Date rolls over', '2026-02-31T12:00:00.000Z:00000000:node-a'],
    ['garbage', 'not a stamp'],
    ['empty string', ''],
    ['empty node', '2026-09-26T12:00:00.000Z:00000000:'],
    ['missing node separator', '2026-09-26T12:00:00.000Z:00000000'],
  ])('rejects %s', (_label, hlc) => {
    expect(parseBoundedHLC(hlc, NOW, DRIFT)).toBeNull()
  })

  // Each of these parses to finite fields with a wall time inside the drift bound, so only
  // the round trip through `HLC.serialize` stands between them and the clock.
  test.each([
    ['2026-09-26T12:00:00.000Z:1:node-a'],
    ['2026-09-26T12:00:00Z:00000000:node-a'],
    ['2026-09-26T12:00:00.000Z:00000001x:node-a'],
    ['2026-09-26T12:00:00.000Z:+0000001:node-a'],
    ['2026-02-31T12:00:00.000Z:00000000:node-a'],
    ['2026-09-26T12:00:00.000Z:00000000'],
  ])('%s parses permissively but is not canonical', (hlc) => {
    const loose = HLC.tryParse(hlc)
    expect(loose).not.toBeNull()
    expect(loose?.wallTime).toBeLessThanOrEqual(NOW + DRIFT)
    expect(parseBoundedHLC(hlc, NOW, DRIFT)).toBeNull()
  })

  test('a canonical far-future stamp is rejected on the drift bound alone', () => {
    const hlc = stamp(NOW + 365 * 24 * 3600 * 1000)
    expect(HLC.serialize(HLC.parse(hlc))).toBe(hlc)
    expect(parseBoundedHLC(hlc, NOW, DRIFT)).toBeNull()
  })

  test('an unparseable stamp answers null rather than throwing', () => {
    // Serializing a NaN wall time throws, so the finite-field check has to run before the
    // round trip.
    expect(() => parseBoundedHLC('Z', NOW, DRIFT)).not.toThrow()
    expect(parseBoundedHLC('Z', NOW, DRIFT)).toBeNull()
    expect(() => parseBoundedHLC('2026-13-01T00:00:00.000Z:00000000:n', NOW, DRIFT)).not.toThrow()
  })

  test.each([
    ['negative', -1],
    ['NaN', Number.NaN],
  ])('a %s drift limit rejects every stamp', (_label, maxDriftMS) => {
    expect(parseBoundedHLC(stamp(NOW - 1000), NOW, maxDriftMS)).toBeNull()
  })

  test('a zero drift limit admits the present and the past only', () => {
    expect(parseBoundedHLC(stamp(NOW), NOW, 0)).not.toBeNull()
    expect(parseBoundedHLC(stamp(NOW - 1), NOW, 0)).not.toBeNull()
    expect(parseBoundedHLC(stamp(NOW + 1), NOW, 0)).toBeNull()
  })

  test('a non-finite now rejects every stamp, since no bound can be measured from it', () => {
    // Every comparison against NaN is false, so an unchecked NaN now would admit any future.
    const future = stamp(NOW + 365 * 24 * 3600 * 1000)
    expect(parseBoundedHLC(future, Number.NaN, DRIFT)).toBeNull()
    expect(parseBoundedHLC(stamp(NOW), Number.POSITIVE_INFINITY, DRIFT)).toBeNull()
  })
})
