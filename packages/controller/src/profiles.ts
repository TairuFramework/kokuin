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
 * A three-syllable handle derived from the DID itself — no stored data, no wordlist, so a cold picker
 * can label profiles with no network or cache. Each syllable is consonant-vowel-consonant, so it is
 * pronounceable; ~30 bits across three, ample to tell a handful of profiles apart and not a security
 * boundary. The label is a function of the identifier, never the reverse (a user label must never
 * feed the DID).
 */
export function handleForDID(did: string): string {
  const digest = sha256(encoder.encode(did))
  const pick = (alphabet: string, byte: number | undefined): string => {
    if (byte === undefined) {
      throw new Error('handleForDID: digest too short')
    }
    return alphabet[byte % alphabet.length] ?? ''
  }
  const syllables: Array<string> = []
  for (let i = 0; i < 3; i++) {
    syllables.push(
      pick(CONSONANTS, digest[i * 3]) +
        pick(VOWELS, digest[i * 3 + 1]) +
        pick(CONSONANTS, digest[i * 3 + 2]),
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
