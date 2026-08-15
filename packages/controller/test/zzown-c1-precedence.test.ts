import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRevokeWithKey,
  createRotate,
  didFromInception,
  type EventCommon,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

describe('branch precedence: current-key revokes never outrank the owning rotate', () => {
  test('a longer run of current-key revokes still loses to the owning rotate', () => {
    const seed = new Uint8Array(32).fill(7)
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)

    // The thief holds the CURRENT authority private key (position 0,0) and nothing else.
    // It cannot rotate — pre-rotation holds — but it can append revokes.
    const stolen = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
    // Annotated, not narrowed by inference: the array is a log and the cursor walks event types,
    // so `[inception]` inferring `SignedEvent<InceptionEvent>[]` made `test:types` fail on the
    // first `push`. Construction below is untouched.
    const thief: Array<SignedEvent> = [inception]
    let prior: EventCommon = inception.event
    for (let n = 0; n < 3; n++) {
      const rev = createRevokeWithKey(stolen.privateKey, did, prior, `did:kokuin:zVictim${n}`)
      thief.push(rev)
      prior = rev.event
    }

    // The owner recovers with the pre-committed next key: one rotate off the inception.
    const owner = [inception, createRotate(seed, 0, did, inception.event)]

    // Both branches fold on their own; the question is which resolution keeps.
    expect(foldLog(did, thief).ok).toBe(true)
    expect(foldLog(did, owner).ok).toBe(true)

    const resolved = resolveBranches(did, [thief, owner])
    expect(resolved.ok).toBe(true)
    if (resolved.ok) {
      // The owner's recovering rotate wins, and its winner folds.
      expect(resolved.winner[resolved.winner.length - 1].event.t).toBe('rot')
      expect(foldLog(did, resolved.winner).ok).toBe(true)
    }
  })
})
