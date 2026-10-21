import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  type EventCommon,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const seed = new Uint8Array(32).fill(1)
const victim = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  return { did, icp }
}

/**
 * A rotate on `prior` whose snapshot denies `deny`. Two of these on one prior with different `deny`
 * are both signed by the pre-committed key — a fork only the controller can have made.
 */
function settle(did: string, prior: EventCommon, deny: Array<string>): SignedEvent {
  return createRotate({
    seed,
    profile: 0,
    did,
    prior,
    options: { snapshot: { members: [], deny } },
  })
}

describe('resolveBranches()', () => {
  test('a longer branch at the same generation wins on sequence', () => {
    const { did, icp } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const result = resolveBranches(did, [[icp], [icp, rot]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toHaveLength(2)
  })

  test('a higher generation wins outright over a longer lower generation', () => {
    const { did, icp } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const denying = settle(did, rot.event, [victim])
    const reset = createReset(seed, 0, 1)
    const result = resolveBranches(did, [
      [icp, rot, denying],
      [icp, reset],
    ])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.winner, 1).event.g).toBe(1)
  })

  test('two different rotates at the same position are duplicity, not a merge', () => {
    // Both reveal the pre-committed key, so neither supersedes the other: the root chain carries
    // only rotates past the inception, and two of them disagreeing is a fork for a reset to settle.
    const { did, icp } = build()
    const rotateA = settle(did, icp.event, [victim])
    const rotateB = settle(did, icp.event, ['did:key:zOther'])
    const result = resolveBranches(did, [
      [icp, rotateA],
      [icp, rotateB],
    ])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.duplicity.gen).toBe(0)
    expect(result.duplicity.seq).toBe(1)
  })

  test('re-derivation is idempotent, so identical branches are not duplicity', () => {
    const { did, icp } = build()
    const a = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const b = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
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

  // Duplicity is reported where the branches actually disagree, which for branches of unequal
  // length is not their heads: the head digests would name events the other branch has no opinion
  // about at all.
  test('duplicity is reported at the divergence point, not at the heads', () => {
    const { did, icp } = build()
    const forkA = settle(did, icp.event, [victim])
    const forkB = settle(did, icp.event, ['did:key:zOther'])
    const forkBNext = settle(did, forkB.event, ['did:key:zThird'])
    const result = resolveBranches(did, [
      [icp, forkA],
      [icp, forkB, forkBNext],
    ])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.duplicity.gen).toBe(0)
    expect(result.duplicity.seq).toBe(1)
    expect(result.duplicity.digests).toEqual([digestOf(forkA.event), digestOf(forkB.event)].sort())
  })

  // A keyless attacker can still author one thing: an unknown, non-critical event, which the fold
  // skips because it cannot know the type's rules. It establishes nothing and must not be able to
  // contend for a position — otherwise appending one to a copy of the inception would turn every
  // honest log into a duplicity report, which is a denial of service on the mechanism that detects
  // a key-takeover fork.
  test('a branch whose only extension is a skipped event cannot force duplicity', () => {
    const { did, icp } = build()
    const honest = [icp, settle(did, icp.event, [victim])]
    const noise = [
      icp,
      {
        event: { v: 1, t: 'nop', i: did, g: 0, s: 1, p: digestOf(icp.event), crit: false },
        sigs: [],
      } as unknown as SignedEvent,
    ]
    expect(foldLog(did, { chain: noise, events: [] }).ok).toBe(true)

    for (const order of [
      [honest, noise],
      [noise, honest],
    ]) {
      const result = resolveBranches(did, order)
      expect(result.ok).toBe(true)
      if (!result.ok) continue
      expect(result.winner).toBe(honest)
      // Nothing of substance was discarded: the skipped event was never state.
      expect(result.superseded).toBe(0)
    }
  })

  // Two branches padded with two *different* skipped events fold to the same head at the same
  // length, so de-duplication has to break the tie on something other than arrival order.
  test('the representative of a de-duplicated head does not depend on presentation order', () => {
    const { did, icp } = build()
    const noise = (tag: string) =>
      [
        icp,
        {
          event: { v: 1, t: tag, i: did, g: 0, s: 1, p: digestOf(icp.event), crit: false },
          sigs: [],
        } as unknown as SignedEvent,
      ] as Array<SignedEvent>
    const a = noise('nop')
    const b = noise('pon')

    const forward = resolveBranches(did, [a, b])
    const backward = resolveBranches(did, [b, a])
    expect(forward.ok && backward.ok).toBe(true)
    if (!forward.ok || !backward.ok) return
    expect(forward.winner).toBe(backward.winner)
    expect(forward.superseded).toBe(backward.superseded)
  })

  // Regression: precedence reads the folded position, never `branch[last].event.g`/`.s`. A skipped
  // event advances neither `gen` nor `seq` in the fold while carrying an `s` of its own on the
  // wire, so a branch padded with one used to read as a position ahead of the branch it is padding.
  test('a branch padded with a skipped event does not outrank the branch it pads', () => {
    const { did, icp } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
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
    expect(foldLog(did, { chain: padded, events: [] }).ok).toBe(true)

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

  // With three contenders at one position, a sequential pairwise reduction could report a different
  // pair depending on which two it compared first. The whole group is resolved at once, so the
  // report — which digests, at which position — must not depend on presentation order.
  test('a three-way fork reports the same duplicity regardless of presentation order', () => {
    const { did, icp } = build()
    const branches = [
      [icp, settle(did, icp.event, [victim])],
      [icp, settle(did, icp.event, ['did:key:zOtherVictim'])],
      [icp, settle(did, icp.event, [])],
    ]
    const orderings = [
      [at(branches, 0), at(branches, 1), at(branches, 2)],
      [at(branches, 0), at(branches, 2), at(branches, 1)],
      [at(branches, 2), at(branches, 0), at(branches, 1)],
    ]
    const first = resolveBranches(did, at(orderings, 0))
    expect(first.ok).toBe(false)
    for (const order of orderings) {
      expect(resolveBranches(did, order)).toEqual(first)
    }
  })

  // Two blind resets at one generation are the same bytes, so they never fork. A snapshot reset and a
  // blind one do: both are the recovery key's, neither outranks the other, and only a reset at a
  // higher generation settles it. Every root-chain divergence is now one of these two shapes — two
  // rotates, or two resets — since the chain carries no current-key event for a rotate to supersede.
  test('a snapshot reset and a blind one at one generation are duplicity until a higher reset', () => {
    const { did, icp } = build()
    const snapshot = [icp, createReset(seed, 0, 1, { members: [], deny: [victim] })]
    const blind = [icp, createReset(seed, 0, 1)]
    const higher = [icp, createReset(seed, 0, 2)]
    const forked = resolveBranches(did, [snapshot, blind])
    expect(forked).toEqual(resolveBranches(did, [blind, snapshot]))
    expect(forked.ok).toBe(false)
    if (forked.ok) return
    expect(forked.failure).toBe('duplicity')
    expect([forked.duplicity.gen, forked.duplicity.seq]).toEqual([1, 0])
    // CONTROL — the same blind reset twice is one history.
    expect(resolveBranches(did, [blind, [icp, createReset(seed, 0, 1)]]).ok).toBe(true)

    const settled = resolveBranches(did, [snapshot, higher, blind])
    expect(settled.ok && settled.winner).toEqual(higher)
  })
})

// A reset chains to the inception, not to the event before it, so the same reset — byte-identical
// when blind, and position-independent with a snapshot too — can sit on different prefixes: a
// verifier appends it to the generation-0 chain it held, while a pruned copy carries it straight
// after the inception and further. What precedes the top generation's reset cannot change the winner
// once both contain it, so the two are one history, and the longer wins in either order.
describe('a reset re-parented onto a different prefix', () => {
  const { did, icp } = build()
  const rot0 = settle(did, icp.event, [])
  for (const [name, reset] of [
    ['blind', createReset(seed, 0, 1)],
    ['with a snapshot', createReset(seed, 0, 1, { members: [], deny: [victim] })],
  ] as const) {
    test(`${name}: the history carried further wins, in either order`, () => {
      const appended = [icp, rot0, reset]
      const carried = [icp, reset, settle(did, reset.event, [])]
      for (const order of [
        [appended, carried],
        [carried, appended],
      ]) {
        const result = resolveBranches(did, order)
        expect(result.ok).toBe(true)
        if (!result.ok) return
        expect(result.winner).toEqual(carried)
        // Only the generation-0 rotate is discarded; the reset both carry is not.
        expect(result.superseded).toBe(1)
      }
    })

    test(`${name}: a rival rotate after the shared reset is still duplicity`, () => {
      const one = [icp, rot0, reset, settle(did, reset.event, ['did:key:zOne'])]
      const two = [icp, reset, settle(did, reset.event, ['did:key:zTwo'])]
      for (const order of [
        [one, two],
        [two, one],
      ]) {
        const result = resolveBranches(did, order)
        expect(result.ok).toBe(false)
        if (result.ok) return
        expect(result.failure).toBe('duplicity')
        expect([result.duplicity.gen, result.duplicity.seq]).toEqual([1, 1])
      }
    })
  }
})
