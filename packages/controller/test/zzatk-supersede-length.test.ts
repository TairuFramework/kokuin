import { describe, expect, test } from 'vitest'

import {
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

const seed = new Uint8Array(32).fill(1)
const victim = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

/**
 * The thief holds the CURRENT authority key the inception established at (0, 0). Every revoke in
 * the run is signed by it: a revoke establishes no new key, so `prior.keys` never moves off the
 * stolen one and the run can be arbitrarily long.
 */
function thiefRun(did: string, icp: SignedEvent, length: number): Array<SignedEvent> {
  const branch: Array<SignedEvent> = [icp]
  let prior = icp.event
  for (let i = 0; i < length; i++) {
    const rev = createRevoke({
      seed,
      profile: 0,
      did,
      prior,
      target: `${victim}${i}`,
      keyPosition: { gen: 0, seq: 0 },
    })
    branch.push(rev)
    prior = rev.event
  }
  return branch
}

/** The owner's recovery: rotate onto the pre-committed next keys, chained `length` times. */
function ownerRun(did: string, icp: SignedEvent, length: number): Array<SignedEvent> {
  const branch: Array<SignedEvent> = [icp]
  let prior = icp.event
  let keySeq = 0
  for (let i = 0; i < length; i++) {
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior,
      options: { keyPosition: { gen: 0, seq: keySeq } },
    })
    branch.push(rot)
    prior = rot.event
    keySeq += 1
  }
  return branch
}

// The attack this file records is closed. The constructions are untouched — the same stolen-key
// run, the same control rows — and only the assertions moved, from "the thief wins" to "the owner
// wins", so the file keeps working as the regression that would notice it reopening.
// `resolveBranches` now compares branches at the point they diverge instead of at their heads, so
// a run of revokes signed by a stolen current key no longer outranks the rotate it forked from.
describe('ATTACK (closed): superseding recovery must not be decided by branch LENGTH', () => {
  test('ROW 1 (attack): a 2-long run of stolen-current-key revokes loses to the owner rotate', () => {
    const { icp, did } = build()
    const thief = thiefRun(did, icp, 2)
    const owner = ownerRun(did, icp, 1)

    const result = resolveBranches(did, [owner, thief])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(foldLog(did, result.winner).ok).toBe(true)
    expect(result.winner).toBe(owner)
    // The thief's whole tail is discarded, not just the event the rotate forked from.
    expect(result.superseded).toBe(2)
  })

  test('ROW 2 (control: at EQUAL length the pre-rotation rule works)', () => {
    const { icp, did } = build()
    const thief = thiefRun(did, icp, 1)
    const owner = ownerRun(did, icp, 1)
    const result = resolveBranches(did, [thief, owner])
    expect(result.ok && result.winner).toBe(owner)
  })

  test('ROW 3 (control: the thief run is valid, not incidentally malformed)', () => {
    const { icp, did } = build()
    const thief = thiefRun(did, icp, 5)
    const r = foldLog(did, thief)
    expect(r.ok).toBe(true)
  })

  test('ROW 4: the owner wins from behind, at every length the thief can reach', () => {
    const { icp, did } = build()
    // However far ahead the thief runs, the divergence point is the same one event, and the owner
    // pre-committed the key that supersedes it there.
    for (const n of [1, 2, 3, 4]) {
      const owner = ownerRun(did, icp, n)
      const thief = thiefRun(did, icp, n + 1)
      const r = resolveBranches(did, [owner, thief])
      expect(r.ok && r.winner).toBe(owner)
    }
  })
})
