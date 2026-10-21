import { digestOf, isCanonicalizable } from './canonical.js'
import {
  type InceptionEvent,
  keyFromTarget,
  keyTarget,
  type RevokeEvent,
  type RotateEvent,
  type SignedEvent,
  verifyInception,
  verifyReset,
  verifyRevoke,
  verifyRotate,
} from './events.js'

export type KeyState = {
  did: string
  gen: number
  seq: number
  /** Generation in which the current `keys` were established. */
  keyGen: number
  /**
   * Derivation index of the current `keys`: key-establishing events this generation, counting the
   * `icp`/`rot` that opened it as 0. Equal to `seq` until a revoke intervenes, and deliberately not
   * the same thing — a revoke advances `seq` while establishing no key, so the pre-rotation chain
   * (which commits the *next* key's digest, one index on) stops tracking `seq` there. Deriving at
   * `seq` after a revoke produces a key the log never committed.
   */
  keySeq: number
  keys: Array<string>
  /** Key agreement keys — an OR set. Established by icp/rot, carried forward across rev. */
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
   * What this position denies, in the two spellings a `rev` target may take — see `RevokeEvent.x`. A
   * `did:…` entry denies a *holder* (`@kokuin/capability` refuses a capability whose `aud` it names);
   * a `#<multibase key>` entry denies a *signer* (`signingKeyFrom` refuses that key, `agreementKeysFrom`
   * drops it).
   *
   * One heterogeneous set rather than two fields: the spellings cannot collide, and every mechanism
   * the set already has (position-dependence, the `d` snapshot, a reset's clear, `resolveDenySet`,
   * the `@kokuin/capability` wrapper that forwards it) then covers keys with nothing new to wire or
   * forget. A second optional resolver member is a second thing a wrapper can drop, and dropping it
   * fails open.
   *
   * **Invariant, enforced by both branches of `stepEvent`: no key in this state's `keys` or
   * `agreement` is denied here.** So every reader may take a folded head's key set at face value.
   */
  deny: ReadonlySet<string>
  /** Digest of the event that produced this state — the `p` any successor must carry. */
  digest: string
}

export type FoldResult =
  | { ok: true; states: Array<KeyState> }
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

    // The deny set this rotate leaves behind: its own snapshot when it carries one (validated by
    // `isPublishedRotate`), else the accumulated set carried forward.
    const denyAfter = rot.event.d == null ? prior.deny : new Set(rot.event.d)
    // A key this event *establishes* must not be one it denies. `d` and the carried-forward set are
    // both attacker-influenced, so without this a single rotate could publish a key and deny it in
    // one breath, and the `KeyState.deny` invariant would hold only by good manners. Failing the fold
    // is the only answer: applying it leaves a head whose `k` resolves to nothing.
    const establishedButDenied = [...rot.event.k, ...rot.event.ka].find((key) =>
      denyAfter.has(keyTarget(key)),
    )
    if (establishedButDenied != null) {
      return { status: 'fail', reason: `rotate establishes a denied key: ${establishedButDenied}` }
    }

    return {
      status: 'ok',
      state: {
        did,
        gen: rot.event.g,
        seq: rot.event.s,
        // New keys are one derivation index on from the last that established one — not at `s`, which
        // any intervening revoke advanced. A reset opens a fresh generation, so its index restarts at
        // 0 (also its `s`).
        keyGen: rot.event.g,
        keySeq: isReset ? 0 : prior.keySeq + 1,
        keys: rot.event.k,
        agreement: rot.event.ka,
        next: rot.event.n,
        // Carried, never replaced — including across a reset. See `KeyState.recovery`.
        recovery: prior.recovery,
        deny: denyAfter,
        digest: digestOf(rot.event),
      },
    }
  }

  if (event.p !== prior.digest) {
    return { status: 'fail', reason: 'event does not chain to the previous digest' }
  }

  if (event.t === 'rev') {
    const rev = signed as SignedEvent<RevokeEvent>
    if (rev.event.g !== prior.gen || rev.event.s !== prior.seq + 1) {
      return { status: 'fail', reason: 'sequence gap' }
    }
    if (typeof rev.event.x !== 'string') {
      return { status: 'fail', reason: 'revoke names no target' }
    }
    // A revoke is authority-signed and nothing else. `cap` is not a member of the event any more; one
    // carried on the wire is refused rather than ignored, so an old capability-authorised revoke
    // stops folding instead of being read as a plain one.
    if ('cap' in rev.event) {
      return { status: 'fail', reason: 'revoke capability is not supported' }
    }
    // A key target may not name a key this position currently publishes. `resolve` is head-only, so
    // a key still in `k` is one the profile asserts it signs with *now*; the event that stops that is
    // `rotate` (whose pre-rotation commitment the leaked-key holder cannot forge), and denial is for
    // what the rotate leaves behind — the historic path, which survives a rotate. So: rotate-then-deny.
    // Allowing it would leave a head whose own `k` the resolver must refuse.
    const deniedKey = keyFromTarget(rev.event.x)
    if (
      deniedKey != null &&
      (prior.keys.includes(deniedKey) || prior.agreement.includes(deniedKey))
    ) {
      return { status: 'fail', reason: `revoke names a key the profile publishes: ${rev.event.x}` }
    }
    const deny = new Set(prior.deny)
    deny.add(rev.event.x)
    // `keyGen`/`keySeq` ride along in the spread: a revoke establishes no key, so the active position
    // is still wherever the last icp/rot put it.
    const state: KeyState = { ...prior, seq: rev.event.s, deny, digest: digestOf(rev.event) }

    if (!verifyRevoke(rev, { digest: prior.digest, keys: prior.keys })) {
      return { status: 'fail', reason: 'invalid revoke' }
    }
    return { status: 'ok', state }
  }

  // Unknown type. Criticality lives in the envelope so this decision needs no understanding of `t`;
  // failing closed on a critical event stops a verifier that does not understand `rev` accepting a
  // revoked device. Only an explicit `crit: false` skips: `crit` is wire data, an absent member is
  // falsy, so a truthiness test would let an attacker claim the skip path by *omitting* the flag. The
  // two reasons separate "declared critical" from "declared nothing".
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
    return { ok: false, result: fail('malformed log', 0) }
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
        digest: digestOf(first.event),
      },
    ],
  }
}

/**
 * Fold a controller's log into per-position key state. `states[i]` is the state *after* `events[i]`,
 * which a verifier evaluating at position `i` must use — that is what makes the deny set
 * position-dependent: clearing a DID later never retroactively validates its earlier actions.
 *
 * Synchronous, so it stays usable on an offline verifier's apply path.
 */
export function foldLog(did: string, events: Array<SignedEvent>): FoldResult {
  const init = initFold(did, events)
  if (!init.ok) {
    return init.result
  }
  const { inception, states } = init
  const budget = skipBudget()

  for (let i = 1; i < events.length; i++) {
    const prior = states[i - 1]
    if (prior === undefined) {
      return fail(INTERNAL_FOLD_INVARIANT, i)
    }
    // `events[i]` may be a hole or `undefined`; `stepEvent` reports that as `malformed event`.
    const outcome = stepEvent(did, inception, events[i] as SignedEvent, prior)
    if (outcome.status === 'fail') {
      return fail(outcome.reason, i)
    }
    if (outcome.skipped) {
      if (!budget.skip()) {
        return fail(TOO_MANY_UNKNOWN_EVENTS, i)
      }
    } else {
      budget.understood()
    }
    states.push(outcome.state)
  }

  return { ok: true, states }
}

export function keyStateAt(result: FoldResult, position: number): KeyState | undefined {
  return result.ok ? result.states[position] : undefined
}

/**
 * The deny set of `state` with `drop` removed — what to pass as a rotate's `denySnapshot` to prune a
 * few entries rather than replace the set. A rotate's `d` replaces the accumulated set outright, so
 * pruning by hand means writing out everything that stays; miss one and the profile silently
 * un-revokes a device or un-retires a leaked key. This builds it from the fold's own answer instead.
 * Entries in `drop` the state does not carry are ignored.
 */
export function pruneDenySet(state: KeyState, drop: Iterable<string>): Array<string> {
  const dropped = new Set(drop)
  return [...state.deny].filter((entry) => !dropped.has(entry))
}
