import type { ResolvedSigningKey } from '@kokuin/token'

import { digestOf } from './canonical.js'
import {
  type InceptionEvent,
  type RevokeEvent,
  type RotateEvent,
  type SignedEvent,
  verifyEventSignedBy,
  verifyInception,
  verifyReset,
  verifyRevoke,
  verifyRotate,
} from './events.js'

export type KeyState = {
  did: string
  gen: number
  seq: number
  /** Generation at which the current `keys` were established — see Amendment A. */
  keyGen: number
  /** Sequence at which the current `keys` were established — see Amendment A. */
  keySeq: number
  keys: Array<string>
  /** Key agreement keys — an OR set. Established by icp/rot, carried forward across rev. */
  agreement: Array<string>
  next: Array<string>
  recovery: string
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
 * `audienceKey` is the signing key the capability names as its audience — pinned in the capability
 * at mint time, never resolved at verification time. The fold checks the event's own signature
 * against it, which is what binds the grant to the party it was issued to.
 *
 * A key rather than a boolean because the fold, not the verifier, must be the one that ties the
 * answer to the event in hand. The log is public — resolving the DID means folding it — so the
 * serialized capability inside a revoke is readable by everyone who can resolve the profile. With
 * a boolean, any such reader could lift it out and chain a revoke of their own, with any bytes at
 * all in `sigs`, covering whatever the capability's `res` covers; a management capability's `res`
 * is a wildcard, so that is every device on the profile.
 *
 * Resolving an audience needs material the fold does not have, and checking a signature over the
 * canonical event bytes needs the event, which the verifier must not be handed. Among divisions
 * that keep a *single* callback, this is the only one where neither side can leave the binding
 * out — a check passed to the verifier as a closure is fail-open the moment a verifier forgets to
 * call it. A two-callback split has the property too, at the price of two answers that must agree
 * about one capability.
 */
export type CapabilityAuthorisation =
  | { authorised: true; audienceKey: ResolvedSigningKey }
  /** `reason` becomes the fold's failure reason verbatim, so it must describe this rejection. */
  | { authorised: false; reason: string }

export type FoldOptions = {
  /**
   * Verify a capability authorising a non-authority signer to revoke. Injected rather than
   * imported so the fold stays free of a capability dependency on the sync path.
   *
   * Receives the serialized capability, the controller DID (which must be the capability `sub`),
   * and the DID being denied. See {@link CapabilityAuthorisation} for what it answers with.
   */
  verifyCapability?: (
    cap: string,
    subject: string,
    target: string,
  ) => Promise<CapabilityAuthorisation>
}

function fail(reason: string, index: number): FoldResult {
  return { ok: false, reason, index }
}

type StepOutcome =
  | { status: 'ok'; state: KeyState }
  | { status: 'fail'; reason: string }
  /**
   * A cap-bearing revoke: `state` is what to apply *if* the capability verifies, and `signed` is
   * the event itself, whose signature must be checked against the key the capability authorises.
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
 * rejection is a returned reason, never a throw. Criticality is decided here, so both fold entry
 * points inherit it: an unknown critical event fails closed, an unknown non-critical one is
 * skipped by carrying the prior state forward unchanged.
 */
function stepEvent(
  did: string,
  inception: InceptionEvent,
  signed: SignedEvent,
  prior: KeyState,
): StepOutcome {
  const event = signed.event

  if (event.i !== did) {
    return { status: 'fail', reason: 'event names a different controller' }
  }

  if (event.t === 'rot') {
    const rot = signed as SignedEvent<RotateEvent>
    const isReset = rot.event.g > prior.gen

    if (isReset) {
      // A reset chains to the inception, not to the head — Amendment A. That is what lets a root
      // holding only its seed author one: `p` is recomputable without the log.
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

    return {
      status: 'ok',
      state: {
        did,
        gen: rot.event.g,
        seq: rot.event.s,
        // A rotate (reset included) establishes new keys at its own position.
        keyGen: rot.event.g,
        keySeq: rot.event.s,
        keys: rot.event.k,
        agreement: rot.event.ka,
        next: rot.event.n,
        recovery: rot.event.r ?? prior.recovery,
        deny: rot.event.d == null ? prior.deny : new Set(rot.event.d),
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
    const deny = new Set(prior.deny)
    deny.add(rev.event.x)
    // `keyGen`/`keySeq` ride along in the spread: a revoke establishes no key, so the active
    // position is still wherever the last icp/rot put it.
    const state: KeyState = { ...prior, seq: rev.event.s, deny, digest: digestOf(rev.event) }

    if (rev.event.cap != null) {
      return { status: 'capability', cap: rev.event.cap, target: rev.event.x, state, signed: rev }
    }
    if (!verifyRevoke(rev, { digest: prior.digest, keys: prior.keys })) {
      return { status: 'fail', reason: 'invalid revoke' }
    }
    return { status: 'ok', state }
  }

  // Unknown type. Criticality lives in the envelope precisely so this decision can be made
  // without understanding `t`. Failing closed on a critical event is what stops a verifier that
  // does not understand `rev` from accepting a revoked device.
  if (event.crit) {
    return { status: 'fail', reason: `unknown critical event type: ${String(event.t)}` }
  }
  // Non-critical: skip, carrying state forward unchanged so positions stay aligned with the input
  // array.
  return { status: 'ok', state: { ...prior, digest: prior.digest } }
}

type FoldInit =
  | { ok: true; inception: InceptionEvent; states: Array<KeyState> }
  | { ok: false; result: FoldResult }

/**
 * Validate the inception and seed the state array both fold entry points start from. Shared so
 * the sync/async split begins only where the two loops actually differ.
 */
function initFold(did: string, events: Array<SignedEvent>): FoldInit {
  if (events.length === 0) {
    return { ok: false, result: fail('empty log', 0) }
  }

  const first = events[0] as SignedEvent<InceptionEvent>
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
        keySeq: first.event.s,
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
 * Fold a controller's log into per-position key state.
 *
 * `states[i]` is the state *after* `events[i]`, which is what a verifier evaluating at log
 * position `i` must use. That is what makes the deny set position-dependent: clearing a DID at a
 * later position never retroactively validates its earlier actions.
 *
 * Synchronous, so it stays usable on the apply path of an offline verifier. A capability-
 * authorised revoke needs async verification it cannot do inline, so it fails closed here rather
 * than trusting a capability it cannot check — use `foldLogAsync` when one may be present.
 */
export function foldLog(did: string, events: Array<SignedEvent>): FoldResult {
  const init = initFold(did, events)
  if (!init.ok) {
    return init.result
  }
  const { inception, states } = init

  for (let i = 1; i < events.length; i++) {
    const outcome = stepEvent(did, inception, events[i], states[i - 1])
    if (outcome.status === 'fail') {
      return fail(outcome.reason, i)
    }
    if (outcome.status === 'capability') {
      return fail(`capability-authorised revoke needs an async fold: ${outcome.cap}`, i)
    }
    states.push(outcome.state)
  }

  return { ok: true, states }
}

/**
 * Async counterpart of {@link foldLog}. Shares {@link stepEvent} with the sync fold, so the only
 * difference is what happens with a capability-authorised revoke: this entry point can await
 * `options.verifyCapability` for it instead of failing closed.
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

  for (let i = 1; i < events.length; i++) {
    const outcome = stepEvent(did, inception, events[i], states[i - 1])
    if (outcome.status === 'fail') {
      return fail(outcome.reason, i)
    }
    if (outcome.status === 'capability') {
      if (options.verifyCapability == null) {
        return fail(`capability-authorised revoke needs a verifier: ${outcome.cap}`, i)
      }
      const authorisation = await options.verifyCapability(outcome.cap, did, outcome.target)
      if (!authorisation.authorised) {
        return fail(authorisation.reason, i)
      }
      // The capability authorises its audience, not its bearer. Checked here rather than left to
      // the verifier so that a verifier which simply forgot cannot make the fold accept a revoke
      // from anyone who read the log — see `CapabilityAuthorisation`.
      if (!verifyEventSignedBy(outcome.signed, authorisation.audienceKey)) {
        return fail('revoke is not signed by the capability audience', i)
      }
    }
    states.push(outcome.state)
  }

  return { ok: true, states }
}

export function keyStateAt(result: FoldResult, position: number): KeyState | undefined {
  return result.ok ? result.states[position] : undefined
}
