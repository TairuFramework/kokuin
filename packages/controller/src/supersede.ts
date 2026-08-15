import { digestOf } from './canonical.js'
import { type RotateEvent, type SignedEvent, verifyRotate } from './events.js'
import {
  CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD,
  CAPABILITY_REVOKE_NEEDS_VERIFIER,
  type FoldOptions,
  type FoldResult,
  foldLog,
  foldLogAsync,
  type KeyState,
} from './fold.js'

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

/**
 * Why branch selection could not name a winner.
 *
 * - `duplicity` — two events the controller cannot both have authored at one position. The real
 *   finding, and the only one that says anything is wrong with the log.
 * - `no-valid-branch` — nothing presented folded at all. Not duplicity: the absence of a history.
 * - `needs-capability-verification` — **every** branch presented carries a capability-authorised
 *   revoke this call was not equipped to check, so there is nothing left to compare. The log is
 *   fine; use {@link resolveBranchesAsync} with a `verifyCapability`. A call where only *some*
 *   branches are unverifiable answers with the ones that are, and reports the rest as
 *   {@link ResolveResult.unverified} — see there for why.
 *
 * Added rather than swapped in: `duplicity` still carries the `gen: -1` sentinel position for the
 * two non-duplicity arms, so a caller written against the previous shape keeps telling them apart
 * exactly as before. New callers should switch on this instead — the sentinel says only "not a
 * real position", which is one bit fewer than there are answers.
 */
export type ResolveFailure = 'duplicity' | 'no-valid-branch' | 'needs-capability-verification'

/**
 * How many presented branches this call could not check, and therefore did not compare.
 *
 * Non-zero means the answer is **provisional**: a branch that could not be folded may have
 * superseded the one reported, so a caller acting on a winner — caching it, serving it, treating a
 * duplicity report as evidence — must either re-resolve through {@link resolveBranchesAsync} with a
 * `verifyCapability` or treat the result as unconfirmed. It is zero for every correctly configured
 * call: with a verifier, an honest capability-authorised revoke folds and a forged one is rejected
 * like any other invalid branch.
 *
 * Reported rather than fatal because the alternative is an unauthenticated denial of service on
 * duplicity detection. A capability-bearing revoke reaches the verifier path *before* any signature
 * check — the capability names the signer, so there is nothing to check it against yet — which
 * means a peer holding no key material at all can copy the public inception, append a `rev` with
 * `sigs: []` and a `cap` of arbitrary bytes, and present it. Refusing the whole resolution on that
 * turned a genuine duplicity report between two honest branches into a refusal, for every profile,
 * including profiles that never use the management tier and so have no reason to configure a
 * verifier. Duplicity detection is the mechanism that catches a key-takeover fork; nobody keyless
 * may switch it off.
 *
 * Dropping such a branch cannot hand an attacker a win: a branch that does not fold is not a
 * contender, and a forged one never folds. The exposure it does leave is a *stale* answer — an
 * honest cap-bearing branch that this call could not check, so the winner is an earlier honest head
 * — which is what this count is for.
 */
export type ResolveResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number; unverified: number }
  | { ok: false; failure: ResolveFailure; duplicity: Duplicity; unverified: number }

/**
 * The position reported for a failure that is not a fork. Real comparisons never reach `gen < 0`
 * and a real digest is never the empty string, which is how a caller told these from duplicity
 * before {@link ResolveFailure} existed.
 */
const NO_POSITION: Duplicity = { gen: -1, seq: -1, digests: ['', ''] }

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

/**
 * Whether a branch failed to fold only because this call could not check a capability.
 *
 * Filtering such a branch out as invalid is what switched duplicity detection off for the
 * management tier: a `cap`-bearing revoke is the tier working as designed, not a thief's forgery,
 * and treating the two alike means a healthy profile resolves to "no valid history at all". Matched
 * by prefix against the fold's exported reasons, which is the contract those constants exist for.
 */
export function needsCapabilityVerification(result: FoldResult): boolean {
  return (
    !result.ok &&
    (result.reason.startsWith(CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD) ||
      result.reason.startsWith(CAPABILITY_REVOKE_NEEDS_VERIFIER))
  )
}

function allUnverified(unverified: number): ResolveResult {
  return { ok: false, failure: 'needs-capability-verification', duplicity: NO_POSITION, unverified }
}

function branchFrom(branch: Array<SignedEvent>, result: FoldResult): FoldedBranch | undefined {
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

type Resolution =
  | { ok: true; winner: FoldedBranch }
  | { ok: false; failure: ResolveFailure; duplicity: Duplicity }

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
        failure: 'duplicity',
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
 *
 * This form folds synchronously and so cannot check a capability-authorised revoke. Such a branch is
 * counted in {@link ResolveResult.unverified} and left out of the comparison, and only a call where
 * *every* branch is one answers `failure: 'needs-capability-verification'`.
 *
 * Neither of the two failures that shaped this is available to anyone. Filtering such a branch away
 * as merely invalid reported "no valid history" for a healthy profile — duplicity detection off for
 * every profile using the management tier. Refusing the whole call instead handed the same switch to
 * a keyless attacker, since a `cap`-bearing revoke reaches the verifier path before any signature
 * check: copy the public inception, append a `rev` with no signatures and arbitrary `cap` bytes, and
 * a genuine duplicity report between two honest branches became a refusal. Reporting the count keeps
 * the honest comparison and makes the gap in it visible. The remedy for the gap is unchanged — fold
 * through {@link resolveBranchesAsync} with a verifier, where an honest branch folds and a forged one
 * is rejected like any other.
 */
export function resolveBranches(did: string, branches: Array<Array<SignedEvent>>): ResolveResult {
  const valid: Array<FoldedBranch> = []
  let unverified = 0
  for (const branch of branches) {
    const result = foldLog(did, branch)
    if (needsCapabilityVerification(result)) {
      unverified++
      continue
    }
    const folded = branchFrom(branch, result)
    if (folded != null) {
      valid.push(folded)
    }
  }
  return selectWinner(valid, unverified)
}

/**
 * Async counterpart of {@link resolveBranches}, and the form the management tier needs.
 *
 * A capability-authorised revoke is the whole point of `createRevokeWithKey` and the `cnf` pin, and
 * the sync fold fails closed on one by construction. Resolving branches through it therefore
 * filtered every branch of such a log away as invalid — reporting "no valid history" for a
 * perfectly healthy profile, which is duplicity detection silently switched off for every profile
 * that uses the management tier. There was no async form to reach for.
 *
 * Branches are folded one at a time rather than in parallel: `verifyCapability` is caller-supplied
 * code that may do I/O of its own, and branch counts in a duplicity report are small, so there is
 * nothing to win against the risk of calling a caller's verifier concurrently.
 */
export async function resolveBranchesAsync(
  did: string,
  branches: Array<Array<SignedEvent>>,
  options: FoldOptions = {},
): Promise<ResolveResult> {
  const valid: Array<FoldedBranch> = []
  let unverified = 0
  for (const branch of branches) {
    const result = await foldLogAsync(did, branch, options)
    // Reachable here only with no `verifyCapability` configured — with one, the verifier's own
    // answer decides, and a rejection is an invalid branch like any other. So a correctly configured
    // call always reports `unverified: 0`.
    if (needsCapabilityVerification(result)) {
      unverified++
      continue
    }
    const folded = branchFrom(branch, result)
    if (folded != null) {
      valid.push(folded)
    }
  }
  return selectWinner(valid, unverified)
}

function selectWinner(valid: Array<FoldedBranch>, unverified: number): ResolveResult {
  if (valid.length === 0) {
    // Nothing left to compare. Which of the two answers that is depends on *why* nothing is left:
    // a branch this call was not equipped to check is not evidence that the log has no history, and
    // saying so would report a healthy management-tier profile as historyless.
    return unverified > 0
      ? allUnverified(unverified)
      : { ok: false, failure: 'no-valid-branch', duplicity: NO_POSITION, unverified }
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
    // A duplicity report is provisional in exactly the same way a winner is: a branch this call
    // could not check might have superseded both of the conflicting events.
    return { ...resolved, unverified }
  }

  const { winner } = resolved
  let superseded = 0
  for (const loser of distinct) {
    if (loser !== winner) {
      superseded += loser.spine.length - commonSpine(winner, loser)
    }
  }
  return { ok: true, winner: winner.branch, superseded, unverified }
}
