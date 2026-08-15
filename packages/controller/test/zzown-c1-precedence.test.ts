import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRevokeWithKey,
  createRotate,
  didFromInception,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

describe('C1 independent reproduction', () => {
  test('a longer run of current-key revokes outranks the owning rotate', () => {
    const seed = new Uint8Array(32).fill(7)
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)

    // The thief holds the CURRENT authority private key (position 0,0) and nothing else.
    // It cannot rotate — pre-rotation holds — but it can append revokes.
    const stolen = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
    const thief = [inception]
    let prior = inception.event
    for (let n = 0; n < 3; n++) {
      const rev = createRevokeWithKey(stolen.privateKey, did, prior, `did:kokuin:zVictim${n}`)
      thief.push(rev)
      prior = rev.event
    }

    // The owner recovers with the pre-committed next key: one rotate off the inception.
    const owner = [inception, createRotate(seed, 0, did, inception.event)]

    const thiefFold = foldLog(did, thief)
    const ownerFold = foldLog(did, owner)
    console.log('thief branch folds:', thiefFold.ok, 'head s:', thief[thief.length - 1].event.s)
    console.log('owner branch folds:', ownerFold.ok, 'head s:', owner[owner.length - 1].event.s)

    const resolved = resolveBranches(did, [thief, owner])
    console.log(
      'winner head t:',
      resolved.ok ? resolved.winner[resolved.winner.length - 1].event.t : 'DUPLICITY',
    )
    if (resolved.ok) {
      const final = foldLog(did, resolved.winner)
      console.log(
        'winner deny set:',
        final.ok ? [...final.states[final.states.length - 1].deny] : 'n/a',
      )
    }

    // The property the docstring claims: the owner's recovering rotate wins.
    expect(resolved.ok).toBe(true)
    if (resolved.ok) {
      expect(resolved.winner[resolved.winner.length - 1].event.t).toBe('rot')
    }
  })
})
