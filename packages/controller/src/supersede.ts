import { digestOf } from './canonical.js'
import { type RotateEvent, type SignedEvent, verifyRotate } from './events.js'
import { foldLog } from './fold.js'

export type Duplicity = {
  gen: number
  seq: number
  digests: [string, string]
}

export type ResolveResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number }
  | { ok: false; duplicity: Duplicity }

function head(branch: Array<SignedEvent>): { gen: number; seq: number } {
  const last = branch[branch.length - 1].event
  return { gen: last.g, seq: last.s }
}

/**
 * Does `candidate` supersede `incumbent` at the same position?
 *
 * Per KERI, a rotate signed by the pre-committed next keys outranks any operation signed by
 * current keys. That is what makes the owner win the race against a thief holding a current
 * authority key regardless of who published first.
 */
function supersedes(
  candidate: SignedEvent,
  incumbent: SignedEvent,
  priorDigest: string,
  priorNext: Array<string>,
): boolean {
  if (candidate.event.t !== 'rot') {
    return false
  }
  if (incumbent.event.t === 'rot') {
    return false
  }
  return verifyRotate(candidate as SignedEvent<RotateEvent>, {
    digest: priorDigest,
    n: priorNext,
  })
}

type TieResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number }
  | { ok: false; duplicity: Duplicity }

/**
 * Resolve every branch tied at the same leading `(gen, seq)` position at once.
 *
 * This must consider the whole tied group together rather than fold it pairwise in arrival
 * order: with three or more contenders, a sequential pairwise reduction can compare two losing
 * branches to each other before it ever reaches the one that legitimately supersedes both,
 * reporting duplicity between the losers and burying the real winner — making the outcome depend
 * on presentation order, which the caller must never observe.
 */
function resolveTie(did: string, contenders: Array<Array<SignedEvent>>): TieResult {
  // Re-derivation is idempotent: branches whose head is byte-identical are the same history
  // presented twice, not distinct contenders. Keep one representative per digest.
  const byDigest = new Map<string, Array<SignedEvent>>()
  for (const branch of contenders) {
    const digest = digestOf(branch[branch.length - 1].event)
    if (!byDigest.has(digest)) {
      byDigest.set(digest, branch)
    }
  }
  const distinct = [...byDigest.values()]

  if (distinct.length === 1) {
    return { ok: true, winner: distinct[0], superseded: 0 }
  }

  const priors = distinct.map((branch) => {
    const result = foldLog(did, branch.slice(0, -1))
    return result.ok ? result.states[result.states.length - 1] : undefined
  })

  let dominant = -1
  for (let i = 0; i < distinct.length; i++) {
    const prior = priors[i]
    if (prior == null) {
      continue
    }
    const candidateHead = distinct[i][distinct[i].length - 1]
    const dominatesAll = distinct.every((other, j) => {
      if (j === i) {
        return true
      }
      return supersedes(candidateHead, other[other.length - 1], prior.digest, prior.next)
    })
    if (dominatesAll) {
      if (dominant !== -1) {
        // More than one branch dominates every other — cannot happen for a legitimate rotate
        // (two distinct rotates never both supersede one another), but fall through to duplicity
        // defensively rather than pick one arbitrarily.
        dominant = -2
        break
      }
      dominant = i
    }
  }

  if (dominant >= 0) {
    return { ok: true, winner: distinct[dominant], superseded: distinct.length - 1 }
  }

  const { gen, seq } = head(distinct[0])
  // Deterministic regardless of arrival order: sort the conflicting digests before reporting.
  const digests = distinct.map((branch) => digestOf(branch[branch.length - 1].event)).sort()
  return { ok: false, duplicity: { gen, seq, digests: [digests[0], digests[1]] } }
}

/**
 * Pick the authoritative branch. Precedence is `(gen, seq)` lexicographic; at an equal leading
 * position, a superseding rotate wins. Anything else at an equal position is duplicity —
 * surfaced rather than merged, because rotation is sequential per controller.
 *
 * `superseded` counts events discarded from losing branches, which is what a cache must
 * invalidate: folded state is not append-only under supersession.
 *
 * Branches that do not fold successfully are filtered out before comparison — a thief who cannot
 * produce a valid event cannot create a duplicity report.
 */
export function resolveBranches(did: string, branches: Array<Array<SignedEvent>>): ResolveResult {
  const valid = branches.filter((branch) => foldLog(did, branch).ok)
  if (valid.length === 0) {
    // No branch folded, so there is nothing to compare — this is not duplicity, it is the
    // absence of any valid history. Reported through the `duplicity` arm (the type has no other
    // failure shape), but at an unambiguous sentinel position: real comparisons never reach
    // `gen < 0`, and a real digest is never the empty string, so a caller can distinguish "no
    // valid branch at all" from a genuine fork by checking `gen < 0` rather than mistaking it for
    // duplicity at the inception.
    return { ok: false, duplicity: { gen: -1, seq: -1, digests: ['', ''] } }
  }

  // Sweep once, tracking the branches tied at the leading `(gen, seq)` position seen so far.
  // Comparing `(gen, seq)` is a strict total order, so this reduction is order-independent on its
  // own; only branches genuinely tied for the lead are deferred to `resolveTie`, which resolves
  // the whole group at once rather than pairwise.
  let leadGen = -1
  let leadSeq = -1
  let contenders: Array<Array<SignedEvent>> = []
  let superseded = 0

  for (const branch of valid) {
    const h = head(branch)
    if (h.gen > leadGen || (h.gen === leadGen && h.seq > leadSeq)) {
      for (const outranked of contenders) {
        superseded += outranked.length
      }
      leadGen = h.gen
      leadSeq = h.seq
      contenders = [branch]
    } else if (h.gen === leadGen && h.seq === leadSeq) {
      contenders.push(branch)
    } else {
      superseded += branch.length
    }
  }

  const resolved = resolveTie(did, contenders)
  if (!resolved.ok) {
    return resolved
  }
  return { ok: true, winner: resolved.winner, superseded: superseded + resolved.superseded }
}
