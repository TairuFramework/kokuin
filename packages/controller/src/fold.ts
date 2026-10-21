import { digestOf, isCanonicalizable } from './canonical.js'
import { foldEpoch } from './epoch.js'
import {
  type InceptionEvent,
  keyFromTarget,
  keyTarget,
  type MemberEntry,
  type RotateEvent,
  type SignedEvent,
  type StateSnapshot,
  verifyInception,
  verifyReset,
  verifyRotate,
} from './events.js'
import { MAX_LOG_EVENTS } from './limits.js'
import { type ControllerLog, isControllerLog, LOG_TOO_LARGE, MALFORMED_LOG } from './log.js'
import { denialTargetsMember, ROTATE_NEEDS_SNAPSHOT, validateSnapshot } from './members.js'

export {
  ROTATE_NEEDS_SNAPSHOT,
  SNAPSHOT_DROPS_RETIRED_KEY,
  SNAPSHOT_MALFORMED,
  SNAPSHOT_MEMBER_DID_MISMATCH,
  SNAPSHOT_MEMBER_KEY_IS_ROOT,
} from './members.js'

/**
 * One management member as a state holds it: the snapshot entry, plus whether a removal has ended
 * it (`removed`) and whether it may act at all (`effective`: present, not removed, and not targeted
 * by any entry of the same state's deny set — see `denialTargetsMember`). A chain state's members are
 * its snapshot's, so none is removed; removal is an epoch effect.
 */
export type MemberState = MemberEntry & { removed: boolean; effective: boolean }

export type KeyState = {
  did: string
  gen: number
  seq: number
  /** Generation in which the current `keys` were established. */
  keyGen: number
  /**
   * Derivation index of the current `keys`: key-establishing events this generation, counting the
   * `icp`/`rot` that opened it as 0. The root chain holds only key-establishing events, so this is
   * `seq`; it is named apart because it answers a different question — where to derive the key, not
   * where the event sits — and an inception's `s` is wire data this package does not derive from.
   */
  keySeq: number
  keys: Array<string>
  /** Key agreement keys — an OR set, established by the same icp/rot as `keys`. */
  agreement: Array<string>
  next: Array<string>
  /**
   * The inception's recovery commitment, carried unchanged through every event. Fixed for the life
   * of the DID, and this field says so because {@link verifyReset} checks the revealed recovery key
   * against `inception.r` and nothing else. A state that disagreed with the verifier would be worse
   * than no state — see {@link RotateEvent} for the `r` that was removed.
   */
  recovery: string
  /**
   * What this position denies, in two spellings. A `did:…` entry denies a *holder*
   * (`@kokuin/capability` refuses a capability whose `aud` it names); a `#<multibase key>` entry
   * ({@link keyTarget}) denies a *signer* (`signingKeyFrom` refuses that key, `agreementKeysFrom` drops
   * it). A chain state's set is exactly its event's snapshot `d` (empty after an inception or a blind
   * reset).
   *
   * One heterogeneous set rather than two fields: the spellings cannot collide, and every mechanism
   * the set already has (position-dependence, the snapshot, a reset's clear, `resolveDenySet`, the
   * `@kokuin/capability` wrapper that forwards it) then covers keys with nothing new to wire or
   * forget. A second optional resolver member is a second thing a wrapper can drop, and dropping it
   * fails open.
   *
   * **Invariant, enforced by the rotate branch of `stepEvent`: no key in this state's `keys` or
   * `agreement` is denied here.** So every reader may take a folded head's key set at face value.
   */
  deny: ReadonlySet<string>
  /**
   * The management set, keyed by each member's `add` digest (its incarnation). A chain state's is its
   * event's snapshot `m`, in snapshot order.
   */
  members: ReadonlyMap<string, MemberState>
  /**
   * Digest of the chain event that opened the epoch this state belongs to. Every chain event opens
   * one, so for a chain state this is its own `digest`; epoch events name it as their `e`.
   */
  epoch: string
  /**
   * Whether the epoch holds more authenticated events than a verifier will evaluate, failing it
   * closed until root settles. A chain state has seen no epoch events, so it is never saturated.
   */
  saturated: boolean
  /** Digest of the event that produced this state — the `p` any successor must carry. */
  digest: string
}

/**
 * `states` is one state per chain event, which is what historic resolution scans. `head` is the last
 * chain state merged with the current epoch: its `deny`, `members` and `saturated` are the live
 * answers. `applied`, `pending` and `rejected` account for the epoch events presented -- the digests
 * that took effect, the well-formed ones still waiting on a parent, and the ones refused (see
 * `FoldEpochResult` for how refusals are counted).
 */
export type FoldResult =
  | {
      ok: true
      states: Array<KeyState>
      head: KeyState
      applied: Array<string>
      pending: number
      rejected: number
    }
  | { ok: false; reason: string; index: number }

function fail(reason: string, index: number): FoldResult {
  return { ok: false, reason, index }
}

/** What a log entry that is not a {@link SignedEvent} at all fails with. */
const MALFORMED_EVENT = 'malformed event'

/**
 * Whether a log entry has the envelope shape everything downstream reads without checking. The
 * fold's input is untrusted (`JSON.parse` of whatever was on the wire), so `signed.event`/`signed.sigs`
 * are assumptions until checked; unchecked they are reachable `TypeError`s, and the worst case is
 * not the throw but that `resolveBranches` filters branches by folding them — so one malformed entry
 * could crash duplicity resolution for every honest branch beside it.
 *
 * Only the envelope is checked here; what the body must contain depends on `t` and stays with each
 * verifier. Canonicalizability is checked here too: every path out canonicalizes the whole body
 * (signature hash, `digestOf`), and both ways it can refuse (`Infinity` from `1e400`, nesting past
 * `MAX_CANONICAL_DEPTH`) arrive as ordinary wire input. Both are the same failure as a bad shape — a
 * `FoldResult`, not an exception from a fold documented total.
 */
function isSignedEventShape(value: unknown): value is SignedEvent {
  if (value == null || typeof value !== 'object') {
    return false
  }
  const signed = value as Partial<SignedEvent>
  if (signed.event == null || typeof signed.event !== 'object') {
    return false
  }
  if (!Array.isArray(signed.sigs) || signed.sigs.some((sig) => typeof sig !== 'string')) {
    return false
  }
  if (signed.recoveryKey !== undefined && typeof signed.recoveryKey !== 'string') {
    return false
  }
  // The body is canonicalized as the top-level value, so this is exactly what the canonicalizer sees.
  return isCanonicalizable(signed.event)
}

type StepOutcome =
  | { status: 'ok'; state: KeyState; skipped?: boolean }
  | { status: 'fail'; reason: string }

/**
 * Validate one event against the state so far and produce the next state. Pure and total — every
 * rejection is a returned reason, never a throw. Criticality is decided here: an unknown critical
 * event fails closed, an unknown `crit: false` event at the next position is skipped (prior state
 * carried forward unchanged), and anything else fails closed.
 */
function stepEvent(
  did: string,
  inception: InceptionEvent,
  signed: SignedEvent,
  prior: KeyState,
  chain: ReadonlyArray<KeyState>,
): StepOutcome {
  if (!isSignedEventShape(signed)) {
    return { status: 'fail', reason: MALFORMED_EVENT }
  }
  const event = signed.event

  if (event.i !== did) {
    return { status: 'fail', reason: 'event names a different controller' }
  }

  if (event.t === 'rot') {
    const rot = signed as SignedEvent<RotateEvent>
    const isReset = rot.event.g > prior.gen

    if (isReset) {
      // A reset chains to the inception, not the head, so `p` is recomputable without the log. This
      // reason is unobservable (`verifyReset` below rejects the same event with `invalid reset`) but
      // stays because `s` is wire data and this states what a reset's sequence must be — do not spend
      // a round trying to reach it.
      if (rot.event.s !== 0) {
        return { status: 'fail', reason: 'reset must restart the sequence' }
      }
      if (!verifyReset(rot, inception)) {
        return { status: 'fail', reason: 'invalid reset' }
      }
    } else {
      if (rot.event.p !== prior.digest) {
        return { status: 'fail', reason: 'event does not chain to the previous digest' }
      }
      if (rot.event.g !== prior.gen || rot.event.s !== prior.seq + 1) {
        return { status: 'fail', reason: 'sequence gap' }
      }
      if (!verifyRotate(rot, { digest: prior.digest, n: prior.next })) {
        return { status: 'fail', reason: 'invalid rotate' }
      }
    }

    // Every rotate is a settlement: the state after it is its snapshot. A non-reset rotate must carry
    // both halves — there is no "carry the prior state forward", since the prior state may hold epoch
    // effects a chain-only verifier cannot reproduce, and half a snapshot would read as "no members"
    // or "no denials" when its author meant neither. A reset without `m` is blind — `verifyReset`
    // admits one only with `d` exactly `[]` — and a blind reset's state is empty.
    if (!isReset && (rot.event.m == null || rot.event.d == null)) {
      return { status: 'fail', reason: ROTATE_NEEDS_SNAPSHOT }
    }
    const snapshot: StateSnapshot =
      rot.event.m == null
        ? { members: [], deny: [] }
        : { members: rot.event.m, deny: rot.event.d ?? [] }

    // The generation's root keys and commitments, this event's included: a reset opens a new
    // generation and is judged against its own keys alone; a rotate against every chain state of its
    // generation. Skipped states repeat their prior, which the sets absorb.
    const generation = isReset ? [] : chain.filter((state) => state.gen === prior.gen)
    const generationKeys = new Set([...rot.event.k, ...rot.event.ka])
    const generationCommitments = new Set(rot.event.n)
    for (const state of generation) {
      for (const key of [...state.keys, ...state.agreement]) generationKeys.add(key)
      for (const commitment of state.next) generationCommitments.add(commitment)
    }
    // Tombstones: the retirements the prior state checkpointed — its key-target denials naming a key
    // this generation's chain established. They must survive every later snapshot in the generation;
    // read off the chain alone, so a pruned and a full store agree. Only a reset clears them.
    const tombstones = new Set<string>()
    if (!isReset) {
      for (const entry of prior.deny) {
        const key = keyFromTarget(entry)
        if (key != null && generationKeys.has(key)) tombstones.add(entry)
      }
    }
    const invalid = validateSnapshot({
      snapshot,
      generationKeys: [...generationKeys],
      generationCommitments: [...generationCommitments],
      recovery: prior.recovery,
      tombstones,
    })
    if (invalid != null) {
      return { status: 'fail', reason: invalid }
    }

    const denyAfter = new Set(snapshot.deny)
    // A key this event *establishes* must not be one it denies. `d` is attacker-influenced wire data,
    // so without this a single rotate could publish a key and deny it in one breath, and the
    // `KeyState.deny` invariant would hold only by good manners. Failing the fold is the only answer:
    // applying it leaves a head whose `k` resolves to nothing.
    const establishedButDenied = [...rot.event.k, ...rot.event.ka].find((key) =>
      denyAfter.has(keyTarget(key)),
    )
    if (establishedButDenied != null) {
      return { status: 'fail', reason: `rotate establishes a denied key: ${establishedButDenied}` }
    }

    // Only the fields a member carries: a snapshot entry is wire data and may hold anything else,
    // which has no meaning to the fold and must not ride into the state as if it had.
    const members = new Map<string, MemberState>()
    for (const { did: memberDID, key, add, lease } of snapshot.members) {
      const entry: MemberEntry = { did: memberDID, key, add, lease }
      const denied = snapshot.deny.some((denial) => denialTargetsMember(denial, entry))
      members.set(add, { ...entry, removed: false, effective: !denied })
    }

    const digest = digestOf(rot.event)
    return {
      status: 'ok',
      state: {
        did,
        gen: rot.event.g,
        seq: rot.event.s,
        // New keys are one derivation index on from the last that established one. A reset opens a
        // fresh generation, so its index restarts at 0 (also its `s`).
        keyGen: rot.event.g,
        keySeq: isReset ? 0 : prior.keySeq + 1,
        keys: rot.event.k,
        agreement: rot.event.ka,
        next: rot.event.n,
        // Carried, never replaced — including across a reset. See `KeyState.recovery`.
        recovery: prior.recovery,
        deny: denyAfter,
        members,
        epoch: digest,
        saturated: false,
        digest,
      },
    }
  }

  if (event.p !== prior.digest) {
    return { status: 'fail', reason: 'event does not chain to the previous digest' }
  }

  // Unknown type — a `rev`, which the chain no longer carries, included. Criticality lives in the
  // envelope so this decision needs no understanding of `t`; failing closed on a critical event stops
  // a verifier that does not understand a type accepting what that type would have refused. Only an
  // explicit `crit: false` skips: `crit` is wire data, an absent member is falsy, so a truthiness test
  // would let an attacker claim the skip path by *omitting* the flag. The two reasons separate
  // "declared critical" from "declared nothing".
  if (event.crit !== false) {
    return {
      status: 'fail',
      reason: event.crit
        ? `unknown critical event type: ${String(event.t)}`
        : `unknown event type with no criticality flag: ${String(event.t)}`,
    }
  }

  // A skipped event is the only one accepted without a signature check, so it must not claim a
  // position it did not earn. `p` is checked above; without this, `g`/`s` were free wire data on an
  // unsigned event, and anything ordering branches by the raw head could be handed
  // `Number.MAX_SAFE_INTEGER` by someone holding no key material.
  if (event.g !== prior.gen || event.s !== prior.seq + 1) {
    return { status: 'fail', reason: 'sequence gap' }
  }

  // Non-critical: skip, carrying state forward so positions stay aligned with the input array. `seq`
  // deliberately does not advance — the skipped event established nothing — so a run of skipped
  // events all claim the same `s`.
  return { status: 'ok', state: { ...prior, digest: prior.digest }, skipped: true }
}

/**
 * How many events a log may carry that this version cannot understand, beyond the number it can.
 *
 * A skipped event is accepted without a signature and advances neither `seq` nor the digest, so
 * nothing about it is authenticated: a relaying peer can insert any number anywhere and the log still
 * folds to the same head. The resolver re-folds on every resolution and a group replays the whole log
 * at every welcome, so an unbounded skip path makes log size — and the verifier's CPU/memory — an
 * attacker's choice. Bounded against the log's own real length so the ceiling stays proportional to
 * work the verifier was doing anyway; the slack keeps a v1 verifier able to fold a log with a few
 * later-version non-critical types near the front, which is the whole point of the skip path.
 */
export const MAX_SKIPPED_SLACK = 8

/** What a log padded past {@link MAX_SKIPPED_SLACK} fails with. */
export const TOO_MANY_UNKNOWN_EVENTS = 'too many unknown events'

/** A fold-loop index landed off the event or state array — a broken invariant, not a bad log. */
export const INTERNAL_FOLD_INVARIANT = 'internal fold invariant: missing event or prior state'

/**
 * The running budget for skipped events. `understood` counts validated events (the inception is the
 * first), `skipped` the ones carried past. Checked as each skipped event arrives, so a padded log
 * stops folding at the point it exceeds the budget rather than after.
 */
function skipBudget(): { understood(): void; skip(): boolean } {
  let understood = 1
  let skipped = 0
  return {
    understood() {
      understood++
    },
    skip() {
      skipped++
      return skipped <= understood + MAX_SKIPPED_SLACK
    },
  }
}

type FoldInit =
  | { ok: true; inception: InceptionEvent; states: Array<KeyState> }
  | { ok: false; result: FoldResult }

/**
 * Validate the inception and seed the state array the fold starts from.
 */
function initFold(did: string, events: Array<SignedEvent>): FoldInit {
  if (!Array.isArray(events)) {
    return { ok: false, result: fail(MALFORMED_LOG, 0) }
  }
  if (events.length === 0) {
    return { ok: false, result: fail('empty log', 0) }
  }

  if (!isSignedEventShape(events[0])) {
    return { ok: false, result: fail(MALFORMED_EVENT, 0) }
  }
  const first = events[0] as SignedEvent<InceptionEvent>
  // Unobservable, like `reset must restart the sequence`: `verifyInception` checks `t` too and
  // rejects the same log with `invalid inception`. Kept because `t` is wire data and this states what
  // a log must open with; recorded as unreachable so the next reader does not hunt for the test.
  if (first.event.t !== 'icp') {
    return { ok: false, result: fail('first event must be an inception', 0) }
  }
  if (!verifyInception(first, did)) {
    return { ok: false, result: fail('invalid inception', 0) }
  }

  return {
    ok: true,
    inception: first.event,
    states: [
      {
        did,
        gen: first.event.g,
        seq: first.event.s,
        keyGen: first.event.g,
        // The derivation index, not the event position — the same number for every inception this
        // package builds (`s` is 0). Writing `s` here would hand a self-certifying log carrying any
        // `s` a `KeyState` naming a key it never committed.
        keySeq: 0,
        keys: first.event.k,
        agreement: first.event.ka,
        next: first.event.n,
        recovery: first.event.r,
        deny: new Set<string>(),
        // The inception opens the first epoch with an empty management set.
        members: new Map<string, MemberState>(),
        epoch: digestOf(first.event),
        saturated: false,
        digest: digestOf(first.event),
      },
    ],
  }
}

/** The chain alone: one state per event, or the first event that does not fold. */
function foldChain(
  did: string,
  events: Array<SignedEvent>,
): { ok: true; states: Array<KeyState> } | { ok: false; result: FoldResult } {
  const init = initFold(did, events)
  if (!init.ok) {
    return init
  }
  const { inception, states } = init
  const budget = skipBudget()

  for (let i = 1; i < events.length; i++) {
    const prior = states[i - 1]
    if (prior === undefined) {
      return { ok: false, result: fail(INTERNAL_FOLD_INVARIANT, i) }
    }
    // `events[i]` may be a hole or `undefined`; `stepEvent` reports that as `malformed event`.
    const outcome = stepEvent(did, inception, events[i] as SignedEvent, prior, states)
    if (outcome.status === 'fail') {
      return { ok: false, result: fail(outcome.reason, i) }
    }
    if (outcome.skipped) {
      if (!budget.skip()) {
        return { ok: false, result: fail(TOO_MANY_UNKNOWN_EVENTS, i) }
      }
    } else {
      budget.understood()
    }
    states.push(outcome.state)
  }

  return { ok: true, states }
}

/**
 * Fold a controller's log into per-position key state. `states[i]` is the state *after* `chain[i]`,
 * which a verifier evaluating at position `i` must use — that is what makes the deny set
 * position-dependent: clearing a DID later never retroactively validates its earlier actions.
 *
 * The epoch events then merge into the chain's last state to give `head` (see `foldEpoch`). Only the
 * request limit can fail that half: more than {@link MAX_LOG_EVENTS} entries is `LOG_TOO_LARGE`, at
 * index -1 because it is no event's fault. Past it, nothing in `log.events` can fail the fold --
 * a bad entry is counted and dropped -- so a relay cannot make a log unfoldable by padding it.
 *
 * Synchronous, so it stays usable on an offline verifier's apply path.
 */
export function foldLog(did: string, log: ControllerLog): FoldResult {
  if (!isControllerLog(log)) {
    return fail(MALFORMED_LOG, 0)
  }
  if (log.events.length > MAX_LOG_EVENTS) {
    return fail(LOG_TOO_LARGE, -1)
  }
  const chain = foldChain(did, log.chain)
  if (!chain.ok) {
    return chain.result
  }
  const { states } = chain
  const merged = foldEpoch({ did, chainStates: states, events: log.events })
  return {
    ok: true,
    states,
    head: merged.head,
    applied: merged.applied,
    pending: merged.pending,
    rejected: merged.rejected,
  }
}

export function keyStateAt(result: FoldResult, position: number): KeyState | undefined {
  return result.ok ? result.states[position] : undefined
}

/**
 * The state snapshot `state` holds, minus `drop` — what to pass as a rotate's `snapshot` to carry the
 * state forward, pruning a few entries rather than replacing it. A rotate's snapshot replaces the
 * state outright, so writing one by hand means writing out everything that stays; miss one and the
 * profile silently un-revokes a device, un-retires a leaked key or dismisses a management member.
 * This builds it from the fold's own answer instead: every member not removed (`drop.members` names
 * members by `add` digest) and every deny entry (`drop.deny`). Entries in `drop` the state does not
 * carry are ignored.
 *
 * Root's tooling owes its user the warnings the fold cannot give: dropping a holder DID denial
 * re-authorises it, safe only once every authority that could have minted it a grant has ended; and
 * a retired root key the chain shows but this deny set lacks is one to add, not to leave out.
 */
export function snapshotOf(
  state: KeyState,
  drop: { deny?: Iterable<string>; members?: Iterable<string> } = {},
): StateSnapshot {
  const droppedDeny = new Set(drop.deny ?? [])
  const droppedMembers = new Set(drop.members ?? [])
  const members: Array<MemberEntry> = []
  for (const member of state.members.values()) {
    if (member.removed || droppedMembers.has(member.add)) continue
    members.push({ did: member.did, key: member.key, add: member.add, lease: member.lease })
  }
  return { members, deny: [...state.deny].filter((entry) => !droppedDeny.has(entry)) }
}
