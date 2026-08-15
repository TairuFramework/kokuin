import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  createInception,
  createReset,
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
  const did = didFromInception(icp.event)
  return { did, icp }
}

describe('resolveBranches()', () => {
  test('a longer branch at the same generation wins on sequence', () => {
    const { did, icp } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const result = resolveBranches(did, [[icp], [icp, rot]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toHaveLength(2)
  })

  test('a higher generation wins outright over a longer lower generation', () => {
    const { did, icp } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const rev = createRevoke(seed, 0, did, rot.event, victim, { gen: 0, seq: 1 })
    const reset = createReset(seed, 0, 1)
    const result = resolveBranches(did, [
      [icp, rot, rev],
      [icp, reset],
    ])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner[1].event.g).toBe(1)
  })

  test('a rotate signed by pre-committed next keys supersedes a current-key event at the same position', () => {
    const { did, icp } = build()
    // The thief holds the current authority key — established by the inception at (0, 0) — and
    // revokes the owner's other device.
    const thiefRevoke = createRevoke(seed, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    // The owner rotates using the pre-committed next keys at the same position.
    const ownerRotate = createRotate(seed, 0, did, icp.event)
    const result = resolveBranches(did, [
      [icp, thiefRevoke],
      [icp, ownerRotate],
    ])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner[1].event.t).toBe('rot')
    expect(result.superseded).toBe(1)
  })

  test('order of presentation does not change the winner', () => {
    const { did, icp } = build()
    const thiefRevoke = createRevoke(seed, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    const ownerRotate = createRotate(seed, 0, did, icp.event)
    const a = resolveBranches(did, [
      [icp, ownerRotate],
      [icp, thiefRevoke],
    ])
    const b = resolveBranches(did, [
      [icp, thiefRevoke],
      [icp, ownerRotate],
    ])
    expect(a.ok && b.ok).toBe(true)
    if (!a.ok || !b.ok) return
    expect(a.winner[1].event.t).toBe(b.winner[1].event.t)
  })

  test('two current-key events at the same position are duplicity, not a merge', () => {
    const { did, icp } = build()
    const revokeA = createRevoke(seed, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    const revokeB = createRevoke(seed, 0, did, icp.event, 'did:key:zOther', { gen: 0, seq: 0 })
    const result = resolveBranches(did, [
      [icp, revokeA],
      [icp, revokeB],
    ])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.duplicity.gen).toBe(0)
    expect(result.duplicity.seq).toBe(1)
  })

  test('re-derivation is idempotent, so identical branches are not duplicity', () => {
    const { did, icp } = build()
    const a = createRotate(seed, 0, did, icp.event)
    const b = createRotate(seed, 0, did, icp.event)
    const result = resolveBranches(did, [
      [icp, a],
      [icp, b],
    ])
    expect(result.ok).toBe(true)
  })

  test('a single branch resolves to itself', () => {
    const { did, icp } = build()
    const result = resolveBranches(did, [[icp]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.superseded).toBe(0)
  })

  // Regression: precedence reads the folded position, never `branch[last].event.g`/`.s`. A skipped
  // event advances neither `gen` nor `seq` in the fold while carrying an `s` of its own on the
  // wire, so a branch padded with one used to read as a position ahead of the branch it is padding.
  test('a branch padded with a skipped event does not outrank the branch it pads', () => {
    const { did, icp } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const honest = [icp, rot]
    // Appended by someone holding no key material: an unknown, non-critical, unsigned event at the
    // next sequence position, which is all the fold can ask of a type it cannot verify.
    const padded = [
      ...honest,
      {
        event: { v: 1, t: 'nop', i: did, g: 0, s: 2, p: digestOf(rot.event), crit: false },
        sigs: [],
      } as unknown as SignedEvent,
    ]
    expect(foldLog(did, padded).ok).toBe(true)

    for (const order of [
      [honest, padded],
      [padded, honest],
    ]) {
      const result = resolveBranches(did, order)
      expect(result.ok).toBe(true)
      if (!result.ok) continue
      // The same folded head, so the two are one history: the shorter representative is kept and
      // nothing is reported as superseded.
      expect(result.winner).toBe(honest)
      expect(result.superseded).toBe(0)
    }
  })

  // Beyond the brief's cases: with two thieves at the same position, a sequential pairwise
  // reduction can compare the two thieves to each other before ever reaching the owner's rotate,
  // reporting duplicity between them and burying the legitimate winner. The order in which the
  // three branches are presented must not change that the owner's rotate wins.
  test('a superseding rotate wins a three-way tie regardless of presentation order', () => {
    const { did, icp } = build()
    const thiefA = createRevoke(seed, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    const thiefB = createRevoke(seed, 0, did, icp.event, 'did:key:zOtherVictim', { gen: 0, seq: 0 })
    const owner = createRotate(seed, 0, did, icp.event)
    const branches = [
      [icp, thiefA],
      [icp, thiefB],
      [icp, owner],
    ]
    const orderings = [
      [branches[0], branches[1], branches[2]],
      [branches[0], branches[2], branches[1]],
      [branches[2], branches[0], branches[1]],
    ]
    for (const order of orderings) {
      const result = resolveBranches(did, order)
      expect(result.ok).toBe(true)
      if (!result.ok) continue
      expect(result.winner[1].event.t).toBe('rot')
      expect(result.superseded).toBe(2)
    }
  })
})
