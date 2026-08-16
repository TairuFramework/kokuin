import type { DIDMethodResolver, ResolvedSigningKey } from '@kokuin/token'

import { digestOf, isCanonicalizable } from './canonical.js'
import {
  type InceptionEvent,
  keyFromTarget,
  keyTarget,
  type RevokeEvent,
  type RotateEvent,
  type SignedEvent,
  verifyEventSignedBy,
  verifyInception,
  verifyReset,
  verifyRevoke,
  verifyRotate,
} from './events.js'
import { createStateResolver } from './state-resolver.js'

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

/**
 * What a capability verifier answers a cap-bearing revoke with.
 *
 * `audienceKey` is the key the capability pins as its audience at mint time, never resolved at
 * verification time; the fold checks the event's own signature against it, binding the grant to the
 * party it was issued to.
 *
 * A key rather than a boolean because the fold, not the verifier, must tie the answer to the event
 * in hand. The log is public, so the serialized capability inside a revoke is readable by everyone
 * who can resolve the profile; with a boolean, any such reader could lift it out and chain a revoke
 * of their own with any bytes in `sigs`, covering whatever the capability's `res` covers — a
 * wildcard, for a management capability, so every device. Among divisions keeping a *single*
 * callback, this is the only one where neither side can leave the binding out.
 */
export type CapabilityAuthorisation =
  | { authorised: true; audienceKey: ResolvedSigningKey }
  /** `reason` becomes the fold's failure reason verbatim, so it must describe this rejection. */
  | { authorised: false; reason: string }

export type FoldOptions = {
  /**
   * Verify a capability authorising a non-authority signer to revoke. Injected rather than imported
   * so the sync path stays free of a capability dependency.
   *
   * Receives the serialized capability, the controller DID (which must be the capability `sub`), the
   * DID being denied, and a resolver for the controller **at the position being verified**. That
   * fourth argument makes the position contract keepable: the capability is issued by the very
   * profile whose log carries the revoke, and the state to resolve it against is the prefix before
   * this event — not the head (which would let a device revoked at event 1 keep authoring at event 2,
   * the deny set being position-dependent only inside the fold) and not the whole log (which would
   * recurse into the asking fold). Nothing outside the fold knows which position is being verified,
   * so the fold answers rather than asks: this resolver holds exactly `states[0..i-1]`, is complete
   * for the profile, and answers `Unknown DID` for anything else so a verifier can merge it into a
   * wider registry for a chain's delegates. See {@link CapabilityAuthorisation}.
   */
  verifyCapability?: (params: VerifyCapabilityParams) => Promise<CapabilityAuthorisation>
}

/** What the fold hands {@link FoldOptions.verifyCapability} — see that member for each field. */
export type VerifyCapabilityParams = {
  cap: string
  subject: string
  target: string
  subjectAtPosition: DIDMethodResolver
}

/**
 * Whether a verifier's answer is one this fold can act on. Total, and strict about both arms: an
 * `authorised: true` with no usable key would reach `verifyEventSignedBy` and throw, an
 * `authorised: false` with no reason would produce a non-string `FoldResult.reason`. Neither is
 * reachable from typed code, both from a stale build.
 *
 * The discriminant is compared against the literals, so a `'true'` string is malformed rather than
 * authorising. The key bytes go through `ArrayBuffer.isView`, not `instanceof Uint8Array`, which is
 * per-realm and would reject a correct answer built in a worker, a `vm` context, or across an
 * Electron bridge — the one way this guard could turn away a good answer.
 */
function isCapabilityAuthorisation(value: unknown): value is CapabilityAuthorisation {
  if (value == null || typeof value !== 'object') {
    return false
  }
  const answer = value as Partial<CapabilityAuthorisation & { audienceKey: unknown }>
  if (answer.authorised === true) {
    const key = answer.audienceKey as ResolvedSigningKey | undefined
    return key != null && typeof key.alg === 'string' && ArrayBuffer.isView(key.publicKey)
  }
  return answer.authorised === false && typeof answer.reason === 'string'
}

function fail(reason: string, index: number): FoldResult {
  return { ok: false, reason, index }
}

/** What a log entry that is not a {@link SignedEvent} at all fails with. */
const MALFORMED_EVENT = 'malformed event'

// The fold's capability-revoke failure reasons. Exported because they already are a contract:
// `@kokuin/capability` asserts on them by string literal across a package boundary. `FoldResult.reason`
// stays a plain string, so these name values rather than widening the type.

/** A verifier threw. The thrown message is appended after `: `, so match with `startsWith`. */
export const CAPABILITY_VERIFIER_FAILED = 'capability verifier failed'

/** A verifier answered with something that is not a {@link CapabilityAuthorisation}. */
export const CAPABILITY_VERIFIER_MALFORMED_ANSWER =
  'capability verifier returned a malformed answer'

/**
 * The capability authorised the revoke and pinned an audience key, and somebody else signed the
 * event. Distinct from a rejected grant: the delegation is sound and the signature is not.
 */
export const REVOKE_NOT_SIGNED_BY_AUDIENCE = 'revoke is not signed by the capability audience'

/**
 * The sync fold met a capability-authorised revoke, which it cannot verify by construction — the
 * management tier working as designed, answered by `foldLogAsync`. The capability follows after `: `,
 * so match with `startsWith`. Exported so speculative folders (`resolveBranches`) can tell it from a
 * genuinely broken log.
 */
export const CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD = 'capability-authorised revoke needs an async fold'

/**
 * The async fold met a capability-authorised revoke with no `verifyCapability` configured. Same
 * shape: the log is fine and the call was not equipped for it.
 */
export const CAPABILITY_REVOKE_NEEDS_VERIFIER = 'capability-authorised revoke needs a verifier'

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
   * A cap-bearing revoke: `state` is what to apply *if* the capability verifies, and `signed` is the
   * event, whose signature must be checked against the key the capability authorises.
   */
  | {
      status: 'capability'
      cap: string
      target: string
      state: KeyState
      signed: SignedEvent<RevokeEvent>
    }

/**
 * Validate one event against the state so far and produce the next state. Pure and total — every
 * rejection is a returned reason, never a throw. Criticality is decided here so both entry points
 * inherit it: an unknown critical event fails closed, an unknown `crit: false` event at the next
 * position is skipped (prior state carried forward unchanged), and anything else fails closed.
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
    // `x` goes into the deny set and, for a cap-authorised revoke, into the verifier as the resource
    // asked for — where a wildcard grant would happily authorise denying `undefined`.
    if (typeof rev.event.x !== 'string') {
      return { status: 'fail', reason: 'revoke names no target' }
    }
    // `cap` crosses a callback boundary into caller-supplied code, the one place a wire value is
    // handed to something that cannot have checked it. `x` above was checked and this was not.
    if (rev.event.cap !== undefined && typeof rev.event.cap !== 'string') {
      return { status: 'fail', reason: 'revoke capability is not a serialized token' }
    }
    // A key target may not name a key this position currently publishes. `resolve` is head-only, so
    // a key still in `k` is one the profile asserts it signs with *now*; the event that stops that is
    // `rotate` (whose pre-rotation commitment the leaked-key holder cannot forge), and denial is for
    // what the rotate leaves behind — the historic path, which survives a rotate. So: rotate-then-deny.
    // Allowing it would let one cap-authorised revoke (wildcard `res`) from a device that never held
    // the sub-seed disable the root tier, and leave a head whose own `k` the resolver must refuse.
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

    if (rev.event.cap != null) {
      return { status: 'capability', cap: rev.event.cap, target: rev.event.x, state, signed: rev }
    }
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

/**
 * The running budget for skipped events, shared by both fold entry points so the two cannot drift.
 * `understood` counts validated events (the inception is the first), `skipped` the ones carried past.
 * Checked as each skipped event arrives, so a padded log stops folding at the point it exceeds the
 * budget rather than after.
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
 * Validate the inception and seed the state array both fold entry points start from. Shared so the
 * sync/async split begins only where the two loops differ.
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
 * Synchronous, so it stays usable on an offline verifier's apply path. A capability-authorised revoke
 * needs async verification, so it fails closed here rather than trusting an unchecked capability — use
 * `foldLogAsync` when one may be present.
 */
export function foldLog(did: string, events: Array<SignedEvent>): FoldResult {
  const init = initFold(did, events)
  if (!init.ok) {
    return init.result
  }
  const { inception, states } = init
  const budget = skipBudget()

  for (let i = 1; i < events.length; i++) {
    const outcome = stepEvent(did, inception, events[i], states[i - 1])
    if (outcome.status === 'fail') {
      return fail(outcome.reason, i)
    }
    if (outcome.status === 'capability') {
      return fail(`${CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD}: ${outcome.cap}`, i)
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

/**
 * Async counterpart of {@link foldLog}. Shares {@link stepEvent}, so the only difference is a
 * capability-authorised revoke: this entry point awaits `options.verifyCapability` instead of failing
 * closed.
 */
export async function foldLogAsync(
  did: string,
  events: Array<SignedEvent>,
  options: FoldOptions = {},
): Promise<FoldResult> {
  const init = initFold(did, events)
  if (!init.ok) {
    return init.result
  }
  const { inception, states } = init
  const budget = skipBudget()

  for (let i = 1; i < events.length; i++) {
    const outcome = stepEvent(did, inception, events[i], states[i - 1])
    if (outcome.status === 'fail') {
      return fail(outcome.reason, i)
    }
    if (outcome.status === 'capability') {
      if (options.verifyCapability == null) {
        return fail(`${CAPABILITY_REVOKE_NEEDS_VERIFIER}: ${outcome.cap}`, i)
      }
      // The fold is total by contract; a verifier is caller-supplied code TypeScript cannot police
      // across a package boundary or a stale build. Both ways it can break the contract — throwing,
      // and answering with the wrong shape — come back as a `FoldResult` with a real reason, never an
      // escaping exception or an `undefined` reason. Our adapter never throws; a third party's need
      // not, and a throw is not evidence the capability authorises anything.
      let authorisation: CapabilityAuthorisation
      try {
        authorisation = await options.verifyCapability({
          cap: outcome.cap,
          subject: did,
          target: outcome.target,
          // A copy: `states` keeps growing, and this resolver must keep answering for the position it
          // was built at even if the verifier holds on to it.
          subjectAtPosition: createStateResolver(did, [...states]),
        })
      } catch (cause) {
        return fail(
          `${CAPABILITY_VERIFIER_FAILED}: ${cause instanceof Error ? cause.message : String(cause)}`,
          i,
        )
      }
      if (!isCapabilityAuthorisation(authorisation)) {
        return fail(CAPABILITY_VERIFIER_MALFORMED_ANSWER, i)
      }
      if (!authorisation.authorised) {
        return fail(authorisation.reason, i)
      }
      // The capability authorises its audience, not its bearer. Checked here rather than left to the
      // verifier so a verifier that simply forgot cannot make the fold accept a revoke from anyone
      // who read the log — see `CapabilityAuthorisation`.
      if (!verifyEventSignedBy(outcome.signed, authorisation.audienceKey)) {
        return fail(REVOKE_NOT_SIGNED_BY_AUDIENCE, i)
      }
    }
    if (outcome.status === 'ok' && outcome.skipped) {
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
