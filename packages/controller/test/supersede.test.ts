import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  type EventCommon,
  type SignedEvent,
} from '../src/events.js'
import { type CapabilityAuthorisation, foldLog } from '../src/fold.js'
import { resolveBranches, resolveBranchesAsync } from '../src/supersede.js'

const seed = new Uint8Array(32).fill(1)
const delegateSeed = new Uint8Array(32).fill(9)
const victim = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const cap = 'a-serialized-capability'

/** Approves the capability, pinning the delegate's signing key as its audience. */
const approve = async (): Promise<CapabilityAuthorisation> => ({
  authorised: true,
  audienceKey: {
    alg: 'EdDSA',
    publicKey: deriveKeyPair(delegateSeed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
  },
})

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  return { did, icp }
}

describe('resolveBranches()', () => {
  test('a longer branch at the same generation wins on sequence', () => {
    const { did, icp } = build()
    const rot = createRotate({ seed, profile: 0, did, prior: icp.event })
    const result = resolveBranches(did, [[icp], [icp, rot]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toHaveLength(2)
  })

  test('a higher generation wins outright over a longer lower generation', () => {
    const { did, icp } = build()
    const rot = createRotate({ seed, profile: 0, did, prior: icp.event })
    const rev = createRevoke({
      seed,
      profile: 0,
      did,
      prior: rot.event,
      target: victim,
      keyPosition: { gen: 0, seq: 1 },
    })
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
    const thiefRevoke = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: victim,
      keyPosition: { gen: 0, seq: 0 },
    })
    // The owner rotates using the pre-committed next keys at the same position.
    const ownerRotate = createRotate({ seed, profile: 0, did, prior: icp.event })
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
    const thiefRevoke = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: victim,
      keyPosition: { gen: 0, seq: 0 },
    })
    const ownerRotate = createRotate({ seed, profile: 0, did, prior: icp.event })
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
    const revokeA = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: victim,
      keyPosition: { gen: 0, seq: 0 },
    })
    const revokeB = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: 'did:key:zOther',
      keyPosition: { gen: 0, seq: 0 },
    })
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
    const a = createRotate({ seed, profile: 0, did, prior: icp.event })
    const b = createRotate({ seed, profile: 0, did, prior: icp.event })
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

  // Regression: branches are compared at the point they diverge, not at their heads. A thief
  // holding a current authority key cannot rotate — pre-rotation holds — but can sign an unlimited
  // run of revokes, each advancing the sequence. Comparing heads made that run outrank the owner's
  // recovering rotate outright, which is the one property superseding recovery exists to provide.
  test('a recovering rotate beats an arbitrarily longer run of current-key events', () => {
    const { did, icp } = build()
    for (const length of [2, 3, 8]) {
      const thief: Array<SignedEvent> = [icp]
      let prior: EventCommon = icp.event
      for (let n = 0; n < length; n++) {
        const rev = createRevoke({
          seed,
          profile: 0,
          did,
          prior,
          target: `${victim}${n}`,
          keyPosition: { gen: 0, seq: 0 },
        })
        thief.push(rev)
        prior = rev.event
      }
      const owner = [icp, createRotate({ seed, profile: 0, did, prior: icp.event })]

      const result = resolveBranches(did, [thief, owner])
      expect(result.ok).toBe(true)
      if (!result.ok) continue
      expect(result.winner).toBe(owner)
      // The rotate supersedes the event it forked from *and* everything the thief piled on after
      // it — KERI's rule is "at that sequence number and every event after it on that branch".
      expect(result.superseded).toBe(length)
      // Nothing the thief denied survives into the authoritative history.
      const folded = foldLog(did, result.winner)
      expect(folded.ok && folded.states[folded.states.length - 1].deny.size).toBe(0)
    }
  })

  // Duplicity is reported where the branches actually disagree, which for branches of unequal
  // length is not their heads: the head digests would name events the other branch has no opinion
  // about at all.
  test('duplicity is reported at the divergence point, not at the heads', () => {
    const { did, icp } = build()
    const forkA = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: victim,
      keyPosition: { gen: 0, seq: 0 },
    })
    const forkB = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: 'did:key:zOther',
      keyPosition: { gen: 0, seq: 0 },
    })
    const forkBNext = createRevoke({
      seed,
      profile: 0,
      did,
      prior: forkB.event,
      target: 'did:key:zThird',
      keyPosition: { gen: 0, seq: 0 },
    })
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
    const honest = [
      icp,
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: icp.event,
        target: victim,
        keyPosition: { gen: 0, seq: 0 },
      }),
    ]
    const noise = [
      icp,
      {
        event: { v: 1, t: 'nop', i: did, g: 0, s: 1, p: digestOf(icp.event), crit: false },
        sigs: [],
      } as unknown as SignedEvent,
    ]
    expect(foldLog(did, noise).ok).toBe(true)

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
    const rot = createRotate({ seed, profile: 0, did, prior: icp.event })
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
    const thiefA = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: victim,
      keyPosition: { gen: 0, seq: 0 },
    })
    const thiefB = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: 'did:key:zOtherVictim',
      keyPosition: { gen: 0, seq: 0 },
    })
    const owner = createRotate({ seed, profile: 0, did, prior: icp.event })
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

// The capability-authorised revoke is the management tier. The sync fold fails closed on one by
// construction, so folding branches through it filtered every branch of such a log away as
// invalid and reported "no valid history at all" — duplicity detection silently off for every
// profile that uses the tier, with no async form to reach for.
describe('resolveBranchesAsync()', () => {
  function capLog() {
    const { did, icp } = build()
    const revoke = createRevoke({
      seed: delegateSeed,
      profile: 0,
      did,
      prior: icp.event,
      target: victim,
      keyPosition: { gen: 0, seq: 0 },
      cap,
    })
    return { did, icp, revoke, branch: [icp, revoke] }
  }

  test('resolves a cap-bearing log the sync form cannot answer for', async () => {
    const { did, branch } = capLog()

    const sync = resolveBranches(did, [branch])
    expect(sync.ok).toBe(false)
    if (sync.ok) return
    // Distinguishable from duplicity, and from a log with no valid history at all.
    expect(sync.failure).toBe('needs-capability-verification')
    expect(sync.duplicity.gen).toBe(-1)

    const result = await resolveBranchesAsync(did, [branch], { verifyCapability: approve })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(branch)
    expect(result.superseded).toBe(0)
  })

  test('reports duplicity on a cap-bearing fork, which the sync form could not see at all', async () => {
    const { did, icp, revoke } = capLog()
    const rival = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: 'did:key:zOther',
      keyPosition: { gen: 0, seq: 0 },
    })
    const branches = [
      [icp, revoke],
      [icp, rival],
    ]

    // The finding the tier exists to make, and the answer the sync form gives instead: the branch it
    // could check, and a count saying it did not see all of them. `unverified` is the whole of what
    // makes that answer safe to act on — without reading it a caller takes a fork for a clean
    // history — and it is why the sync form cannot simply drop such a branch and say nothing.
    expect(resolveBranches(did, branches)).toEqual({
      ok: true,
      winner: [icp, rival],
      superseded: 0,
      unverified: 1,
    })

    const result = await resolveBranchesAsync(did, branches, { verifyCapability: approve })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.failure).toBe('duplicity')
    expect(result.duplicity.gen).toBe(0)
    expect(result.duplicity.seq).toBe(1)
  })

  test('a branch whose capability the verifier declines is filtered, not fatal', async () => {
    // A `cap`-bearing revoke reaches the capability path before any signature check — the
    // capability names the signer — so anyone who can read a log can append one. With a verifier
    // it is rejected and the branch is filtered like any other invalid one, which is what keeps
    // the answer from being a denial of service on duplicity detection.
    const { did, icp } = capLog()
    const honest = [
      icp,
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: icp.event,
        target: victim,
        keyPosition: { gen: 0, seq: 0 },
      }),
    ]
    const forged = [
      icp,
      {
        ...createRevoke({
          seed,
          profile: 0,
          did,
          prior: icp.event,
          target: 'did:key:zForged',
          keyPosition: { gen: 0, seq: 0 },
          cap,
        }),
        sigs: [],
      },
    ]

    const result = await resolveBranchesAsync(did, [honest, forged], {
      verifyCapability: async () => ({ authorised: false, reason: 'no such grant' }),
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(honest)
  })

  test('answers needs-capability-verification when no verifier is configured', async () => {
    const { did, branch } = capLog()
    expect(await resolveBranchesAsync(did, [branch])).toEqual({
      ok: false,
      failure: 'needs-capability-verification',
      duplicity: { gen: -1, seq: -1, digests: ['', ''] },
      unverified: 1,
    })
  })

  test('matches the sync form on every log that carries no capability', async () => {
    const { did, icp } = build()
    const rot = createRotate({ seed, profile: 0, did, prior: icp.event })
    const thief = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: victim,
      keyPosition: { gen: 0, seq: 0 },
    })
    const reset = createReset(seed, 0, 1)
    for (const branches of [
      [[icp]],
      [[icp], [icp, rot]],
      [
        [icp, thief],
        [icp, rot],
      ],
      [
        [icp, rot],
        [icp, reset],
      ],
    ]) {
      expect(await resolveBranchesAsync(did, branches)).toEqual(resolveBranches(did, branches))
    }
  })
})
