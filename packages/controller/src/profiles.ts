import { sha256 } from '@noble/hashes/sha2.js'

import { createInception, didFromInception } from './events.js'

export type ProfileEntry = {
  index: number
  did: string
  handle: string
}

const encoder = new TextEncoder()

// Frozen forever: a handle a user wrote down must keep resolving to the same profile. Letters
// that are easily confused when read aloud or handwritten are left out — no c/k or q, no i/l.
const CONSONANTS = 'bdfghjkmnprstvwz'
const VOWELS = 'aeou'

/**
 * A three-syllable handle derived from the DID itself. No stored data and no wordlist to keep in
 * sync across apps — which is what lets a cold picker label profiles with no network and no cache.
 *
 * Each syllable is consonant-vowel-consonant, so the handle is pronounceable and can be read out
 * or written down. 16 x 4 x 16 per syllable gives 1024 combinations, about 30 bits across three —
 * ample to tell a handful of profiles apart, and not a security boundary.
 *
 * A user label must never feed the DID, so this is the inverse: the label is a function of the
 * identifier, not the other way round.
 */
export function handleForDID(did: string): string {
  const digest = sha256(encoder.encode(did))
  const syllables: Array<string> = []
  for (let i = 0; i < 3; i++) {
    syllables.push(
      CONSONANTS[digest[i * 3] % CONSONANTS.length] +
        VOWELS[digest[i * 3 + 1] % VOWELS.length] +
        CONSONANTS[digest[i * 3 + 2] % CONSONANTS.length],
    )
  }
  return syllables.join('-')
}

/**
 * Enumerate the first `count` profiles for a seed.
 *
 * Every index yields a valid-looking DID whether or not the profile was ever used — which
 * profiles were used is not seed-derived. A picker should present all of them and let a probe
 * grey out the unused ones when a group, hub, or cache is reachable.
 */
export function enumerateProfiles(seed: Uint8Array, count: number): Array<ProfileEntry> {
  if (!Number.isInteger(count) || count < 1) {
    throw new Error('enumerateProfiles: count must be at least 1')
  }
  const entries: Array<ProfileEntry> = []
  for (let index = 0; index < count; index++) {
    const did = didFromInception(createInception(seed, index).event)
    entries.push({ index, did, handle: handleForDID(did) })
  }
  return entries
}
