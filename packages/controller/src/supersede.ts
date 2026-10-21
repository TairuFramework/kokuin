import { digestOf } from './canonical.js'
import type { SignedEvent } from './events.js'
import { type FoldResult, foldLog, type KeyState } from './fold.js'

/** Index into an array whose element is a branch-resolution invariant, throwing rather than reading undefined. */
function required<T>(items: ReadonlyArray<T>, index: number, what: string): T {
  const item = items[index]
  if (item === undefined) {
    throw new Error(`supersede: ${what}`)
  }
  return item
}

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
 *
 * `duplicity` still carries the `gen: -1` sentinel for the non-duplicity arm, so a caller tells them
 * apart.
 */
export type ResolveFailure = 'duplicity' | 'no-valid-branch'

export type ResolveResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number }
  | { ok: false; failure: ResolveFailure; duplicity: Duplicity }

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
  return required(states, states.length - 1, 'folded branch has no state')
}

/** The digest of the `j`th event on the spine — the whole history up to it, chained. */
function spineDigest(folded: FoldedBranch, j: number): string {
  const index = required(folded.spine, j, 'spine index out of range')
  return required(folded.states, index, 'spine points past folded state').digest
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
    if (required(states, i, 'state gap').digest !== required(states, i - 1, 'state gap').digest) {
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
    digestOf(required(candidate.branch, candidate.branch.length - 1, 'empty branch').event) <
    digestOf(required(incumbent.branch, incumbent.branch.length - 1, 'empty branch').event)
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

type Resolution =
  | { ok: true; winner: FoldedBranch }
  | { ok: false; failure: ResolveFailure; duplicity: Duplicity }

/**
 * Walk the contenders down to one, deciding at each divergence point rather than at the heads. A
 * contender ending at the divergence point is a prefix of the others and drops out; once every
 * remaining contender carries an event there, they disagree on it, and nothing on the root chain can
 * settle that within a generation — the chain holds only `icp` and `rot`, and two rotates at one
 * position (or two resets at one generation) are both signed by keys only the controller holds,
 * neither outranking the other. That is duplicity, for a reset at a higher generation to resolve.
 *
 * The whole surviving group is judged at once rather than pairwise, so the report is the same in every
 * presentation order. The group shrinks strictly each iteration, so this terminates.
 */
function resolveContenders(contenders: Array<FoldedBranch>): Resolution {
  let group = contenders

  while (group.length > 1) {
    const pivot = required(group, 0, 'empty contender group')
    // Where they first disagree, against the group as a whole — the point every contender agrees to.
    let divergence = pivot.spine.length
    for (const folded of group.slice(1)) {
      divergence = Math.min(divergence, commonSpine(pivot, folded))
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

    // Every contender carries an event at the divergence point and at least two differ: two events the
    // controller cannot both have authored. Deterministic regardless of arrival order: sort the
    // conflicting digests, report from the branch sorted first.
    const digests = [...new Set(group.map((folded) => spineDigest(folded, divergence)))].sort()
    const firstDigest = required(digests, 0, 'no diverging digests')
    const secondDigest = required(digests, 1, 'duplicity needs two digests')
    const reporter = group.find(
      (folded) => spineDigest(folded, divergence) === firstDigest,
    ) as FoldedBranch
    const at = required(
      reporter.states,
      required(reporter.spine, divergence, 'spine index out of range'),
      'divergence points past folded state',
    )
    return {
      ok: false,
      failure: 'duplicity',
      duplicity: { gen: at.gen, seq: at.seq, digests: [firstDigest, secondDigest] },
    }
  }

  return { ok: true, winner: required(group, 0, 'empty contender group') }
}

/**
 * Pick the authoritative root chain among `chains` — chains only: epoch events never fork the log, so
 * they are never a branch to choose between (see `mergeLogs` in `log.ts`). Two rules, in order:
 *
 * 1. The highest folded generation wins outright. Only a reset raises the generation, and only the
 *    committed recovery key can author a reset — the root's override, unreachable by a thief.
 * 2. Within that generation, chains are compared **at the point they diverge**, not at their heads. A
 *    chain that ends at the divergence point is a prefix of the other and loses to it; two chains
 *    that each carry an event there are duplicity, surfaced rather than merged.
 *
 * With root adds and root revokes moved into epochs, the chain holds only `icp` and `rot`, so the
 * second case is always two rotates, or two resets at one generation — both signed by keys only the
 * controller holds, neither outranking the other, and settled only by a reset at a higher generation.
 * The current-key event a cold rotate outranks still exists, but in the epoch that rotate closes,
 * where the fold gives it no effect; branch selection never sees it. That is also why chain length
 * never decides anything here: the one resource a thief holding a current key has in abundance is
 * current-key events, and none of them is on the chain. A longer chain still wins when it is the same
 * history carried further, which the divergence walk sees as a prefix.
 *
 * `superseded` counts the state-advancing events discarded from losing chains (what a cache must
 * invalidate — folded state is not append-only under supersession); skipped events are not counted.
 * Chains that do not fold are filtered out before comparison, so a thief who cannot produce a valid
 * event cannot create a duplicity report.
 */
export function resolveBranches(did: string, chains: Array<Array<SignedEvent>>): ResolveResult {
  const valid: Array<FoldedBranch> = []
  for (const branch of chains) {
    const folded = branchFrom(branch, foldLog(did, { chain: branch, events: [] }))
    if (folded != null) {
      valid.push(folded)
    }
  }
  return selectWinner(valid)
}

function selectWinner(valid: Array<FoldedBranch>): ResolveResult {
  if (valid.length === 0) {
    return { ok: false, failure: 'no-valid-branch', duplicity: NO_POSITION }
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
