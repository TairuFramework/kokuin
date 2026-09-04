import { describe, expect, test } from 'vitest'

import { createInception, didFromInception } from '../src/events.js'
import { enumerateProfiles, handleForDID } from '../src/profiles.js'

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const seed = new Uint8Array(32).fill(1)
const other = new Uint8Array(32).fill(2)

describe('enumerateProfiles()', () => {
  test('derives the requested number of profiles', () => {
    expect(enumerateProfiles(seed, 5)).toHaveLength(5)
  })

  test('indexes are contiguous from zero', () => {
    expect(enumerateProfiles(seed, 3).map((p) => p.index)).toEqual([0, 1, 2])
  })

  test('DIDs match the inception-derived identifiers', () => {
    const first = at(enumerateProfiles(seed, 1), 0)
    expect(first.did).toBe(didFromInception(createInception(seed, 0).event))
  })

  test('is a pure function of the seed — the picker works offline', () => {
    expect(enumerateProfiles(seed, 3)).toEqual(enumerateProfiles(seed, 3))
  })

  test('different seeds produce different profiles', () => {
    expect(at(enumerateProfiles(seed, 1), 0).did).not.toBe(at(enumerateProfiles(other, 1), 0).did)
  })

  test('rejects a non-positive count', () => {
    expect(() => enumerateProfiles(seed, 0)).toThrow(/at least 1/)
  })
})

describe('handleForDID()', () => {
  test('is three hyphenated three-letter syllables', () => {
    expect(handleForDID(at(enumerateProfiles(seed, 1), 0).did)).toMatch(
      /^[a-z]{3}-[a-z]{3}-[a-z]{3}$/,
    )
  })

  test('every syllable is consonant-vowel-consonant, so it is pronounceable', () => {
    for (const { did } of enumerateProfiles(seed, 20)) {
      for (const syllable of handleForDID(did).split('-')) {
        expect(syllable[1]).toMatch(/[aeiou]/)
        expect(syllable[0]).not.toMatch(/[aeiou]/)
        expect(syllable[2]).not.toMatch(/[aeiou]/)
      }
    }
  })

  test('is stable for the same DID', () => {
    const { did } = at(enumerateProfiles(seed, 1), 0)
    expect(handleForDID(did)).toBe(handleForDID(did))
  })

  test('differs between profiles so a user can tell them apart', () => {
    const profiles = enumerateProfiles(seed, 2)
    const a = at(profiles, 0)
    const b = at(profiles, 1)
    expect(handleForDID(a.did)).not.toBe(handleForDID(b.did))
  })
})
