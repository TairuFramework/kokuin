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
 * - `duplicity` — two events the controller cannot both have authored at one position. The only one
 *   that says anything is wrong with the log.
 * - `no-valid-branch` — nothing presented folded at all.
 * - `needs-capability-verification` — **every** branch carries a capability-authorised revoke this
 *   call was not equipped to check, so there is nothing left to compare. The log is fine; use
 *   {@link resolveBranchesAsync} with a `verifyCapability`. A call where only *some* branches are
 *   unverifiable answers with the rest and reports the count as {@link ResolveResult.unverified}.
 *
 * Added rather than swapped in: `duplicity` still carries the `gen: -1` sentinel for the two
 * non-duplicity arms, so a caller written against the previous shape still tells them apart.
 */
export type ResolveFailure = 'duplicity' | 'no-valid-branch' | 'needs-capability-verification'

/**
 * How many presented branches this call could not check, and therefore did not compare.
 *
 * Non-zero means the answer is **provisional**: an unfoldable branch may have superseded the one
 * reported, so a caller acting on a winner must re-resolve through {@link resolveBranchesAsync} with
 * a `verifyCapability` or treat the result as unconfirmed. Zero for every correctly configured call.
 *
 * Reported rather than fatal because the alternative is an unauthenticated DoS on duplicity
 * detection. A cap-bearing revoke reaches the verifier path *before* any signature check (the
 * capability names the signer), so a keyless peer can copy the public inception, append a `rev` with
 * `sigs: []` and arbitrary `cap` bytes, and present it — and refusing the whole resolution on that
 * would turn a genuine duplicity report between two honest branches into a refusal, for every
 * profile. Dropping such a branch cannot hand an attacker a win (a branch that does not fold is not a
 * contender); the only exposure left is a *stale* answer, which this count marks.
 */
export type ResolveResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number; unverified: number }
  | { ok: false; failure: ResolveFailure; duplicity: Duplicity; unverified: number }

/**
 * The position reported for a failure that is not a fork. Real comparisons never reach `gen < 0` and
 * a real digest is never the empty string — how a caller told these from duplicity before
 * {@link ResolveFailure} existed.
 */
const NO_POSITION: Duplicity = { gen: -1, seq: -1, digests: ['', ''] }

/**
 * A branch that folded, paired with what the fold made of it. Everything this module compares comes
 * from the fold, never the raw events: read off a raw event, `(g, s)` is wire data on an event whose
 * signature may never have been checked (a skipped event is accepted without one), so a keyless
 * attacker could name `Number.MAX_SAFE_INTEGER` and outrank every real branch.
 */
type FoldedBranch = {
  branch: Array<SignedEvent>
  states: Array<KeyState>
  /**
   * Indices into `branch` of the events that moved the fold — all but the skipped ones. The spine,
   * not the array, is a branch's history: a skipped event establishes nothing and must not contend
   * for a position, else a keyless attacker could append one unsigned unknown event to a copy of the
   * inception and have it read as a rival history at position 1. `spine[0]` is always 0 (every valid
   * branch of one log shares the inception whose digest is the DID).
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
 * Whether a branch failed to fold only because this call could not check a capability. Filtering such
 * a branch out as invalid is what switched duplicity detection off for the management tier — a
 * `cap`-bearing revoke is the tier working as designed, not a forgery. Matched by prefix against the
 * fold's exported reasons, the contract those constants exist for.
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
    // A skipped event is the only one that leaves the digest where it was; every other chains its
    // predecessor's digest into its body, so no two can agree.
    if (states[i].digest !== states[i - 1].digest) {
      spine.push(i)
    }
  }
  return { branch, states, spine }
}

/**
 * Which of two branches that fold to the same head to keep. A total order, so the answer never
 * depends on which arrived first.
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
 * How far two branches agree, in spine entries. Zero is unreachable for branches of one log (they
 * share an inception), so a common prefix of 1 means they forked immediately after it.
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
 * Does `candidate` supersede `incumbent` at the point their branches diverge? Per KERI, a rotate
 * signed by the pre-committed next keys outranks any current-key operation — at the diverging
 * position *and* over everything after it on the losing branch. That is what makes the owner win the
 * race against a thief holding a current key regardless of who published first or how far ahead: a
 * stolen current key cannot rotate but can sign revokes all day, so length must not decide this.
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
 * Walk the contenders down to one, deciding at each divergence point rather than at the heads. Every
 * step resolves the *whole* surviving group at once: with three or more contenders, a sequential
 * pairwise reduction could compare two losing branches before reaching the one that supersedes both,
 * reporting duplicity between the losers and making the outcome depend on presentation order. The
 * group shrinks strictly each iteration, so this terminates.
 */
function resolveContenders(contenders: Array<FoldedBranch>): Resolution {
  let group = contenders

  while (group.length > 1) {
    // Where they first disagree, against the group as a whole — the point every contender agrees to.
    let divergence = group[0].spine.length
    for (const folded of group.slice(1)) {
      divergence = Math.min(divergence, commonSpine(group[0], folded))
    }

    // A branch ending at the divergence point is a prefix of the others: extended, not contradicted,
    // so it loses without any event discarded. The ordinary "one peer is behind" case, and the only
    // way a longer branch wins.
    const extended = group.filter(({ spine }) => spine.length > divergence)
    if (extended.length === 0) {
      // Every contender is exactly the common prefix — the same history, already de-duplicated.
      // Unreachable; take the first rather than spin.
      break
    }
    if (extended.length < group.length) {
      group = extended
      continue
    }

    // Group the contenders by the event they diverge on. Branches sharing one are decided further
    // down.
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

    // The state the diverging events all chain to. Identical across contenders, so any can answer.
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
          // More than one branch dominates every other — impossible for a legitimate rotate (two
          // distinct rotates never both supersede one another), but fall through to duplicity
          // defensively rather than pick arbitrarily.
          dominant = -2
          break
        }
        dominant = i
      }
    }

    if (dominant < 0) {
      // Two events the controller cannot both have authored, no rotate to settle it. Deterministic
      // regardless of arrival order: sort the conflicting digests, report from the branch sorted
      // first.
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
 * Pick the authoritative branch. Two rules, in order:
 *
 * 1. The highest folded generation wins outright. Only a reset raises the generation, and only the
 *    committed recovery key can author a reset — the root's override, unreachable by a thief.
 * 2. Within that generation, branches are compared **at the point they diverge**, not at their heads:
 *    a rotate signed by the pre-committed next keys supersedes the current-key event it forked from
 *    and everything that branch accumulated. Two diverging events with no rotate to settle them are
 *    duplicity, surfaced rather than merged.
 *
 * Comparing heads instead would make branch *length* decisive below the top generation — the one
 * resource a thief has in abundance (a stolen current key cannot rotate but can sign unlimited
 * revokes). A longer branch still wins when it is the same history carried further, which the
 * divergence walk sees as a prefix.
 *
 * `superseded` counts the state-advancing events discarded from losing branches (what a cache must
 * invalidate — folded state is not append-only under supersession); skipped events are not counted.
 * Branches that do not fold are filtered out before comparison, so a thief who cannot produce a valid
 * event cannot create a duplicity report.
 *
 * This form folds synchronously and cannot check a capability-authorised revoke: such a branch is
 * counted in {@link ResolveResult.unverified} and left out, and only a call where *every* branch is
 * one answers `failure: 'needs-capability-verification'`. See {@link ResolveResult.unverified} for
 * why the count is reported rather than fatal; the remedy is {@link resolveBranchesAsync} with a
 * verifier.
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
 * Async counterpart of {@link resolveBranches}, and the form the management tier needs — the sync
 * fold fails closed on a capability-authorised revoke, so resolving through it would filter every
 * branch of such a log away as invalid and report "no valid history" for a healthy profile.
 *
 * Branches are folded one at a time: `verifyCapability` is caller-supplied code that may do I/O, and
 * branch counts in a duplicity report are small, so there is nothing to win against calling a
 * caller's verifier concurrently.
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
    // Reachable only with no `verifyCapability` configured — with one, the verifier's answer decides
    // and a rejection is an invalid branch. So a correctly configured call always reports
    // `unverified: 0`.
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
    // Nothing left to compare, and which answer that is depends on *why*: an unchecked branch is not
    // evidence the log has no history.
    return unverified > 0
      ? allUnverified(unverified)
      : { ok: false, failure: 'no-valid-branch', duplicity: NO_POSITION, unverified }
  }

  // Re-derivation is idempotent: branches folding to the same head are one history presented twice.
  // The shortest representative wins, lexicographically smaller raw head at equal length — picking by
  // arrival order would be the presentation dependence the caller must never observe. Both arms are
  // reachable: a reset chains to the inception, so anyone can re-parent a published one onto a longer
  // prefix; and two branches padded with different skipped events fold to the same head at one length.
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
    // A duplicity report is provisional the same way a winner is: an unchecked branch might have
    // superseded both conflicting events.
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
