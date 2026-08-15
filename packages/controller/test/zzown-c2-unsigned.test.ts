import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

describe('keyless branch hijack, independent reproduction', () => {
  test('an unsigned unknown non-critical event with a spoofed position wins branch selection', () => {
    const seed = new Uint8Array(32).fill(11)
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)

    // The honest history: rotate, then revoke a device.
    const rotate = createRotate(seed, 0, did, inception.event)
    const revoke = createRevoke(seed, 0, did, rotate.event, 'did:key:zVictimDevice', {
      gen: 0,
      seq: 1,
    })
    const honest = [inception, rotate, revoke]

    // The attacker holds NO key material. It takes the public inception and appends one
    // unsigned event of an unknown type, with a fabricated position.
    const forged = {
      event: {
        v: 1,
        t: 'nop',
        i: did,
        g: Number.MAX_SAFE_INTEGER,
        s: Number.MAX_SAFE_INTEGER,
        p: digestOf(inception.event),
        crit: false,
      },
      // Not a signature over anything.
      sigs: ['zzzznotasignature'],
    } as unknown as SignedEvent
    const attack = [inception, forged]

    console.log('honest folds:', foldLog(did, honest).ok)
    console.log('attack folds:', foldLog(did, attack).ok)

    const resolved = resolveBranches(did, [honest, attack])
    if (resolved.ok) {
      const types = resolved.winner.map((e) => e.event.t)
      const final = foldLog(did, resolved.winner)
      console.log('winner event types:', types)
      console.log('honest events discarded:', resolved.superseded)
      console.log(
        'winner deny set:',
        final.ok ? [...final.states[final.states.length - 1].deny] : 'n/a',
      )
    } else {
      console.log('duplicity:', resolved.duplicity)
    }

    // The honest branch must win.
    expect(resolved.ok).toBe(true)
    if (resolved.ok) {
      expect(resolved.winner[resolved.winner.length - 1].event.t).toBe('rev')
    }
  })
})
