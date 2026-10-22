import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { createInception, createRotate, didFromInception, type SignedEvent } from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

describe('keyless branch hijack, independent reproduction', () => {
  test('an unsigned unknown non-critical event with a spoofed position wins branch selection', () => {
    const seed = new Uint8Array(32).fill(11)
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)

    // The honest history: rotate, then rotate again denying a device.
    const rotate = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const denying = createRotate({
      seed,
      profile: 0,
      did,
      prior: rotate.event,
      snapshot: { members: [], deny: ['did:key:zVictimDevice'] },
    })
    const honest = [inception, rotate, denying]

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

    const resolved = resolveBranches(did, [honest, attack])
    // The honest branch must win, and its winner folds.
    expect(resolved.ok).toBe(true)
    if (resolved.ok) {
      const head = resolved.winner[resolved.winner.length - 1]
      if (head === undefined) throw new Error('expected a winning event')
      expect(head).toBe(denying)
      expect(foldLog(did, { chain: resolved.winner, events: [] }).ok).toBe(true)
    }
  })
})
