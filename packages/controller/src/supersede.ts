import { type RotateEvent, type SignedEvent, verifyRotate } from './events.js'
import { foldLog, type KeyState } from './fold.js'

export type Duplicity = {
  gen: number
  seq: number
  digests: [string, string]
}

export type ResolveResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number }
  | { ok: false; duplicity: Duplicity }

/**
 * A branch that folded, paired with the position the fold put it at.
 *
 * The *folded* position, never `branch[last].event.g`/`.s`: the fold is the only thing in this
 * package that has validated anything, and precedence is what decides which history is
 * authoritative. Read off the raw event, `(g, s)` is wire data on an event whose signature may
 * never have been checked at all — a skipped event is accepted without one — so an attacker holding
 * no key material could name `Number.MAX_SAFE_INTEGER` and outrank every branch the controller can
 * ever author. A skipped event also does not advance `seq`, which the raw read got wrong in the
 * honest direction too.
 */
type FoldedBranch = {
  branch: Array<SignedEvent>
  states: Array<KeyState>
  head: { gen: number; seq: number }
}

/** The digest the fold ended on — the `p` any successor to this branch would have to carry. */
function headDigest({ states }: FoldedBranch): string {
  return states[states.length - 1].digest
}

function foldBranch(did: string, branch: Array<SignedEvent>): FoldedBranch | undefined {
  const result = foldLog(did, branch)
  if (!result.ok) {
    return undefined
  }
  const last = result.states[result.states.length - 1]
  return { branch, states: result.states, head: { gen: last.gen, seq: last.seq } }
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
function resolveTie(contenders: Array<FoldedBranch>): TieResult {
  // Re-derivation is idempotent: branches that fold to the same head are the same history
  // presented twice, not distinct contenders. Keep one representative per digest.
  //
  // The *folded* head digest, for the reason `FoldedBranch` gives. It chains the whole meaningful
  // history — every event that moves state contributes its own digest to the next — and a skipped
  // event carries the prior one forward, so two branches agreeing on it differ only in events the
  // fold ignored. Keyed on the raw head event instead, a branch padded with an unsigned skipped
  // event read as a rival history rather than as the same one with junk appended.
  const byDigest = new Map<string, FoldedBranch>()
  for (const folded of contenders) {
    const digest = headDigest(folded)
    const kept = byDigest.get(digest)
    // The shortest representative, and the first one at equal length: same folded head means the
    // extra events changed nothing, and picking by arrival order is exactly the presentation
    // dependence the caller must never observe. It is reachable — a reset chains to the inception,
    // not to the head, so anyone can re-parent a published one onto a longer prefix of their own
    // and offer that as the same head.
    if (kept == null || folded.branch.length < kept.branch.length) {
      byDigest.set(digest, folded)
    }
  }
  const distinct = [...byDigest.values()]

  if (distinct.length === 1) {
    return { ok: true, winner: distinct[0].branch, superseded: 0 }
  }

  // The state before each branch's head event, which is what a superseding rotate is verified
  // against. Already computed: `states[i]` is the state after `branch[i]`, so the prior is one
  // back. A branch that is nothing but its inception has no prior and can supersede nothing.
  const priors = distinct.map(({ states }) =>
    states.length >= 2 ? states[states.length - 2] : undefined,
  )

  let dominant = -1
  for (let i = 0; i < distinct.length; i++) {
    const prior = priors[i]
    if (prior == null) {
      continue
    }
    const candidateHead = distinct[i].branch[distinct[i].branch.length - 1]
    const dominatesAll = distinct.every((other, j) => {
      if (j === i) {
        return true
      }
      return supersedes(
        candidateHead,
        other.branch[other.branch.length - 1],
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

  if (dominant >= 0) {
    return { ok: true, winner: distinct[dominant].branch, superseded: distinct.length - 1 }
  }

  const { gen, seq } = distinct[0].head
  // Deterministic regardless of arrival order: sort the conflicting digests before reporting.
  const digests = distinct.map(headDigest).sort()
  return { ok: false, duplicity: { gen, seq, digests: [digests[0], digests[1]] } }
}

/**
 * Pick the authoritative branch. Precedence is the *folded* `(gen, seq)` lexicographic — see
 * {@link FoldedBranch} for why it is never read off the raw head event; at an equal leading
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

  // Sweep once, tracking the branches tied at the leading `(gen, seq)` position seen so far.
  // Comparing `(gen, seq)` is a strict total order, so this reduction is order-independent on its
  // own; only branches genuinely tied for the lead are deferred to `resolveTie`, which resolves
  // the whole group at once rather than pairwise.
  let leadGen = -1
  let leadSeq = -1
  let contenders: Array<FoldedBranch> = []
  let superseded = 0

  for (const folded of valid) {
    const h = folded.head
    if (h.gen > leadGen || (h.gen === leadGen && h.seq > leadSeq)) {
      for (const outranked of contenders) {
        superseded += outranked.branch.length
      }
      leadGen = h.gen
      leadSeq = h.seq
      contenders = [folded]
    } else if (h.gen === leadGen && h.seq === leadSeq) {
      contenders.push(folded)
    } else {
      superseded += folded.branch.length
    }
  }

  const resolved = resolveTie(contenders)
  if (!resolved.ok) {
    return resolved
  }
  return { ok: true, winner: resolved.winner, superseded: superseded + resolved.superseded }
}
