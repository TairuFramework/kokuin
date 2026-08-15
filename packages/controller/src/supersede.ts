import { digestOf } from './canonical.js'
import { type RotateEvent, type SignedEvent, verifyRotate } from './events.js'
import { foldLog, type KeyState } from './fold.js'

export type Duplicity = {
  /** Position of the divergence, from the folded state of the first conflicting event. */
  gen: number
  seq: number
  /**
   * Digests of the two conflicting events *at the divergence point*, sorted — not of the branch
   * heads, which for branches of unequal length say nothing about where they disagree.
   */
  digests: [string, string]
}

export type ResolveResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number }
  | { ok: false; duplicity: Duplicity }

/**
 * A branch that folded, paired with what the fold made of it.
 *
 * Everything this module compares comes from the fold, never from the raw events: the fold is the
 * only thing in this package that has validated anything, and branch selection is what decides
 * which history is authoritative. Read off a raw event, `(g, s)` is wire data on an event whose
 * signature may never have been checked at all — a skipped event is accepted without one — so an
 * attacker holding no key material could name `Number.MAX_SAFE_INTEGER` and outrank every branch
 * the controller can ever author.
 */
type FoldedBranch = {
  branch: Array<SignedEvent>
  states: Array<KeyState>
  /**
   * Indices into `branch` of the events that moved the fold — every event except the skipped ones,
   * which carry the prior digest forward unchanged.
   *
   * The spine, not the array, is a branch's history. A skipped event is of a type the fold cannot
   * even verify a signature for; it establishes nothing, occupies no position, and must therefore
   * not be able to contend with a real event for one. Comparing raw arrays instead, a keyless
   * attacker could append one unsigned unknown event to a copy of the inception and have that read
   * as a rival history at position 1 — turning every honest log into a duplicity report.
   *
   * `spine[0]` is always 0: a branch that folds has an inception whose digest is the DID, so every
   * valid branch of one log starts from the same event.
   */
  spine: Array<number>
}

function headState({ states }: FoldedBranch): KeyState {
  return states[states.length - 1]
}

/** The digest of the `j`th event on the spine — the whole history up to it, chained. */
function spineDigest(folded: FoldedBranch, j: number): string {
  return folded.states[folded.spine[j]].digest
}

function foldBranch(did: string, branch: Array<SignedEvent>): FoldedBranch | undefined {
  const result = foldLog(did, branch)
  if (!result.ok) {
    return undefined
  }
  const { states } = result
  const spine = [0]
  for (let i = 1; i < states.length; i++) {
    // A skipped event is the only one that leaves the digest where it was: every other event
    // chains its predecessor's digest into its own body, so no two can agree.
    if (states[i].digest !== states[i - 1].digest) {
      spine.push(i)
    }
  }
  return { branch, states, spine }
}

/**
 * Which of two branches that fold to the same head to keep. A total order on branches, so the
 * answer never depends on which arrived first.
 */
function preferred(candidate: FoldedBranch, incumbent: FoldedBranch): boolean {
  if (candidate.branch.length !== incumbent.branch.length) {
    return candidate.branch.length < incumbent.branch.length
  }
  return (
    digestOf(candidate.branch[candidate.branch.length - 1].event) <
    digestOf(incumbent.branch[incumbent.branch.length - 1].event)
  )
}

/**
 * How far two branches agree, counted in spine entries.
 *
 * Zero is unreachable for branches of one log — they share an inception — so a common prefix of 1
 * means they forked immediately after it.
 */
function commonSpine(a: FoldedBranch, b: FoldedBranch): number {
  const shortest = Math.min(a.spine.length, b.spine.length)
  let j = 0
  while (j < shortest && spineDigest(a, j) === spineDigest(b, j)) {
    j++
  }
  return j
}

/**
 * Does `candidate` supersede `incumbent` at the point their branches diverge?
 *
 * Per KERI, a rotate signed by the pre-committed next keys outranks any operation signed by
 * current keys — at the diverging position *and* over everything that follows it on the losing
 * branch. That is what makes the owner win the race against a thief holding a current authority
 * key regardless of who published first, and regardless of how far the thief has run ahead: a
 * stolen current key cannot rotate, but it can sign revokes all day, so length is exactly what
 * must not decide this.
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

type Resolution = { ok: true; winner: FoldedBranch } | { ok: false; duplicity: Duplicity }

/**
 * Walk the contenders down to one, deciding at each divergence point rather than at the heads.
 *
 * Every step resolves the *whole* surviving group at once rather than folding it pairwise in
 * arrival order: with three or more contenders, a sequential pairwise reduction can compare two
 * losing branches to each other before it ever reaches the one that legitimately supersedes both,
 * reporting duplicity between the losers and burying the real winner — making the outcome depend
 * on presentation order, which the caller must never observe.
 *
 * The group shrinks strictly on every iteration, so this terminates.
 */
function resolveContenders(contenders: Array<FoldedBranch>): Resolution {
  let group = contenders

  while (group.length > 1) {
    // Where they first disagree. Taken against the group as a whole, so it is the point every
    // remaining contender agrees up to.
    let divergence = group[0].spine.length
    for (const folded of group.slice(1)) {
      divergence = Math.min(divergence, commonSpine(group[0], folded))
    }

    // A branch that ends at the divergence point is a prefix of the others: it has been extended,
    // not contradicted, so it loses without any of its events being discarded. This is the
    // ordinary "one peer is behind" case, and the only way a longer branch wins.
    const extended = group.filter(({ spine }) => spine.length > divergence)
    if (extended.length === 0) {
      // Every contender is exactly the common prefix, so they are the same history — already
      // removed by de-duplication. Unreachable; take the first rather than spin.
      break
    }
    if (extended.length < group.length) {
      group = extended
      continue
    }

    // Group the contenders by the event they diverge on. Branches sharing one agree this far and
    // are decided further down.
    const rivals = new Map<string, Array<FoldedBranch>>()
    for (const folded of group) {
      const digest = spineDigest(folded, divergence)
      const bucket = rivals.get(digest)
      if (bucket == null) {
        rivals.set(digest, [folded])
      } else {
        bucket.push(folded)
      }
    }
    const groups = [...rivals.values()]

    // The state the diverging events all chain to. Identical across contenders — they agree on
    // every event that produced it — so any of them can answer for it.
    const first = groups[0][0]
    const prior = first.states[first.spine[divergence] - 1]

    let dominant = -1
    for (let i = 0; i < groups.length; i++) {
      const candidate = groups[i][0].branch[groups[i][0].spine[divergence]]
      const dominatesAll = groups.every((other, j) => {
        if (j === i) {
          return true
        }
        return supersedes(
          candidate,
          other[0].branch[other[0].spine[divergence]],
          prior.digest,
          prior.next,
        )
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

    if (dominant < 0) {
      // Two events the controller cannot both have authored at one position, and no rotate to
      // settle it. Deterministic regardless of arrival order: sort the conflicting digests, and
      // report the position from the branch the sort puts first.
      const digests = groups.map((members) => spineDigest(members[0], divergence)).sort()
      const reporter = groups.find(
        (members) => spineDigest(members[0], divergence) === digests[0],
      ) as Array<FoldedBranch>
      const at = reporter[0].states[reporter[0].spine[divergence]]
      return {
        ok: false,
        duplicity: { gen: at.gen, seq: at.seq, digests: [digests[0], digests[1]] },
      }
    }

    group = groups[dominant]
  }

  return { ok: true, winner: group[0] }
}

/**
 * Pick the authoritative branch.
 *
 * Two rules, in this order:
 *
 * 1. The highest folded generation wins outright. Only a reset raises the generation, and only the
 *    committed recovery key can author a reset, so this is the root's override and nothing a
 *    thief holds can reach it.
 * 2. Within that generation, branches are compared **at the point they diverge**, not at their
 *    heads: a rotate signed by the pre-committed next keys supersedes the current-key event it
 *    forked from, and with it every event that branch went on to accumulate. Two events at the
 *    divergence point with no rotate to settle them are duplicity — surfaced rather than merged,
 *    because rotation is sequential per controller.
 *
 * Comparing heads instead made branch *length* the deciding factor below the top generation, which
 * is the one resource a thief has in abundance: a stolen current key cannot rotate, but it can
 * sign an unlimited run of revokes, each advancing the sequence, until the owner's recovering
 * rotate sits hopelessly behind. A longer branch still wins the case it should — when it is the
 * same history carried further, which the divergence walk sees as a prefix.
 *
 * `superseded` counts the state-advancing events discarded from losing branches, which is what a
 * cache must invalidate: folded state is not append-only under supersession. Events the fold
 * skipped are not counted; discarding them invalidates nothing.
 *
 * Branches that do not fold successfully are filtered out before comparison — a thief who cannot
 * produce a valid event cannot create a duplicity report.
 */
export function resolveBranches(did: string, branches: Array<Array<SignedEvent>>): ResolveResult {
  const valid: Array<FoldedBranch> = []
  for (const branch of branches) {
    const folded = foldBranch(did, branch)
    if (folded != null) {
      valid.push(folded)
    }
  }
  if (valid.length === 0) {
    // No branch folded, so there is nothing to compare — this is not duplicity, it is the
    // absence of any valid history. Reported through the `duplicity` arm (the type has no other
    // failure shape), but at an unambiguous sentinel position: real comparisons never reach
    // `gen < 0`, and a real digest is never the empty string, so a caller can distinguish "no
    // valid branch at all" from a genuine fork by checking `gen < 0` rather than mistaking it for
    // duplicity at the inception.
    return { ok: false, duplicity: { gen: -1, seq: -1, digests: ['', ''] } }
  }

  // Re-derivation is idempotent: branches that fold to the same head are the same history
  // presented twice, not distinct contenders. The folded head digest chains the whole spine, so
  // agreeing on it means differing only in events the fold ignored.
  //
  // The shortest representative wins, and the lexicographically smaller raw head at equal length:
  // same folded head means the extra events changed nothing, so picking by arrival order would be
  // exactly the presentation dependence the caller must never observe. Both arms are reachable — a
  // reset chains to the inception, not to the head, so anyone can re-parent a published one onto a
  // longer prefix of their own and offer that as the same head; and two branches padded with two
  // *different* skipped events fold to the same head at the same length.
  const byHead = new Map<string, FoldedBranch>()
  for (const folded of valid) {
    const digest = headState(folded).digest
    const kept = byHead.get(digest)
    if (kept == null || preferred(folded, kept)) {
      byHead.set(digest, folded)
    }
  }
  const distinct = [...byHead.values()]

  const topGen = Math.max(...distinct.map((folded) => headState(folded).gen))
  const resolved = resolveContenders(distinct.filter((f) => headState(f).gen === topGen))
  if (!resolved.ok) {
    return resolved
  }

  const { winner } = resolved
  let superseded = 0
  for (const loser of distinct) {
    if (loser !== winner) {
      superseded += loser.spine.length - commonSpine(winner, loser)
    }
  }
  return { ok: true, winner: winner.branch, superseded }
}
