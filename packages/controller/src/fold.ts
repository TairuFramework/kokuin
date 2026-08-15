import type { DIDMethodResolver, ResolvedSigningKey } from '@kokuin/token'

import { digestOf, isCanonicalizable } from './canonical.js'
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
import { createStateResolver } from './state-resolver.js'

export type KeyState = {
  did: string
  gen: number
  seq: number
  /** Generation in which the current `keys` were established — see Amendment A. */
  keyGen: number
  /**
   * Derivation index of the current `keys`: how many key-establishing events this generation has
   * had, counting the `icp`/`rot` that opened it as 0 — see Amendment A.
   *
   * Equal to `seq` until a revoke intervenes, and deliberately not the same thing. A revoke
   * advances `seq` while establishing no key, so the pre-rotation chain — which commits the digest
   * of the *next* key, one derivation index on — stops tracking `seq` at that point. Deriving at
   * `seq` after a revoke produces a key the log never pre-committed: an unverifiable token from
   * `createControllerIdentity`, and a rotate that cannot fold at all.
   */
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
   * the DID being denied, and a resolver for the controller **at the position being verified**.
   * See {@link CapabilityAuthorisation} for what it answers with.
   *
   * The fourth argument is what makes the position contract keepable. A capability authorising a
   * revoke is issued by the very profile whose log carries that revoke, so verifying it means
   * resolving that profile — and the state to resolve it against is neither the head nor the whole
   * log but the prefix before this event. The head would let a device the log revoked at event 1
   * keep authoring revokes at event 2, since the deny set is only position-dependent inside the
   * fold; the whole log would send resolution back into the fold that is asking. Nothing outside
   * the fold knows which position is being verified — `loadLog` is handed a DID and nothing else —
   * so the fold answers rather than asks: this resolver holds exactly `states[0..i-1]`, is
   * complete for the profile (keys by `kid`, deny set, agreement keys), and answers `Unknown DID`
   * for anything else, so a verifier can merge it into a wider registry for the delegates in a
   * chain.
   *
   * A verifier that ignores it is back to resolving the profile some other way, which is the
   * failure this argument exists to remove — `createControllerCapabilityVerifier` prefers it over
   * its own registry for the subject.
   */
  verifyCapability?: (
    cap: string,
    subject: string,
    target: string,
    subjectAtPosition: DIDMethodResolver,
  ) => Promise<CapabilityAuthorisation>
}

/**
 * Whether a verifier's answer is one this fold can act on. Total, and deliberately strict about
 * both arms: an `authorised: true` with no usable key would reach `verifyEventSignedBy` and throw,
 * and an `authorised: false` with no reason would produce a `FoldResult` whose `reason` is not a
 * string. Neither is reachable from typed code; both are reachable from a stale build.
 *
 * The discriminant is compared against the literals rather than tested for truthiness, so a
 * `'true'` string — the shape an untyped caller reaches for — is malformed rather than authorising.
 * The key bytes go through `ArrayBuffer.isView` instead of `instanceof Uint8Array`: `instanceof`
 * is per-realm, so a correct answer built in a worker, a `vm` context or across an Electron bridge
 * would otherwise be rejected as malformed — the one way this guard can turn away a good answer.
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

// The fold's failure reasons for a capability-authorised revoke. Exported because they already are
// a contract: `@kokuin/capability` asserts on them by string literal across a package boundary,
// which is what not exporting them looks like from the outside. Telling "the grant was rejected"
// from "the capability is malformed for this use" from "your verifier is broken" should not mean
// hardcoding English sentences. `FoldResult.reason` stays a plain string, so these name values
// rather than widening the type.

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
 * The sync fold met a capability-authorised revoke, which it cannot verify by construction. The
 * capability follows after `: `, so match with `startsWith`.
 *
 * Not a defect in the log: this is the management tier working as designed, and the answer is
 * `foldLogAsync`. Exported because callers that fold speculatively — `resolveBranches`, which must
 * not quietly treat such a branch as invalid — have to tell it from a log that is actually broken.
 */
export const CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD = 'capability-authorised revoke needs an async fold'

/**
 * The async fold met a capability-authorised revoke with no `verifyCapability` configured. Same
 * shape, same reason for existing: the log is fine and the call was not equipped for it.
 */
export const CAPABILITY_REVOKE_NEEDS_VERIFIER = 'capability-authorised revoke needs a verifier'

/**
 * Whether a log entry has the envelope shape everything downstream reads without checking.
 *
 * The fold's input is untrusted by definition — a log arrives from a network peer or an untrusted
 * store, and `JSON.parse` produces whatever was on the wire — so `signed.event` and `signed.sigs`
 * are assumptions until something checks them. Unchecked they are several reachable `TypeError`s,
 * and the worst consequence is not the throw: `resolveBranches` filters branches by folding them,
 * so a thief who cannot produce a valid event could still crash duplicity resolution for every
 * well-formed branch — a denial of service on the one mechanism that detects a key-takeover fork.
 *
 * Only the envelope is checked here. What the event *body* must contain depends on `t`, so that
 * stays with each verifier.
 *
 * Whether the body can be canonicalized at all is checked here too. Every path out of this function
 * canonicalizes the whole body — the signature check hashes it, `digestOf` chains it — so a body
 * the canonicalizer refuses is one this function's callers cannot proceed on, and both of the ways
 * it refuses arrive as ordinary wire input. Nesting: the canonicalizer recurses once per level and
 * `JSON.parse` accepts unbounded depth, so an event carrying a member the fold never reads still
 * decides how much stack it uses. Numbers: `1e400` parses to `Infinity`, which has no encoding —
 * and reached `canonicalize` as a *throw*, from inside a fold documented total, which one hostile
 * branch used to take `resolveBranches` down for every honest branch beside it.
 *
 * Both are the same failure as a bad shape: an event body this package could not have produced and
 * cannot hash is a malformed event, and says so with a `FoldResult` rather than an exception.
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
  // The body is what gets canonicalized, and it is canonicalized as the top-level value — so what
  // is judged here is exactly what the canonicalizer will be handed.
  return isCanonicalizable(signed.event)
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
 * points inherit it: an unknown critical event fails closed, an unknown event declaring
 * `crit: false` at the next sequence position is skipped by carrying the prior state forward
 * unchanged, and an unknown event that does neither fails closed too.
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
      // A reset chains to the inception, not to the head — Amendment A. That is what lets a root
      // holding only its seed author one: `p` is recomputable without the log.
      //
      // This reason is unobservable and no test can elicit it: `verifyReset` on the next line
      // rejects the same event with `invalid reset`, so removing the check changes the reason and
      // nothing else. It stays because `s` is wire data and this is the check that says what a
      // reset's sequence must be — see the rule at `verifyEventSignedBy` — but do not spend a round
      // trying to reach it.
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
        // A rotate establishes new keys one derivation index on from the last one that did — not
        // at its own `s`, which any intervening revoke has already advanced. A reset opens a fresh
        // generation, so its index restarts at 0 (which is also its `s`).
        keyGen: rot.event.g,
        keySeq: isReset ? 0 : prior.keySeq + 1,
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
    // The one member of a revoke the fold reads rather than verifies. It goes into the deny set —
    // a `ReadonlySet<string>` — and, for a capability-authorised revoke, into the verifier as the
    // resource being asked for, where a wildcard grant would happily authorise denying `undefined`.
    if (typeof rev.event.x !== 'string') {
      return { status: 'fail', reason: 'revoke names no target' }
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
  //
  // Only an explicit `crit: false` means "skip me". `crit` is wire data like everything else here,
  // and an absent member reads as `undefined` — falsy — so a truthiness test let an attacker who
  // simply *omitted* the flag claim the skip path for an event nobody could have understood. A
  // criticality that cannot be read is not a criticality, so anything but `false` fails closed;
  // the two reasons separate "declared critical" from "declared nothing".
  if (event.crit !== false) {
    return {
      status: 'fail',
      reason: event.crit
        ? `unknown critical event type: ${String(event.t)}`
        : `unknown event type with no criticality flag: ${String(event.t)}`,
    }
  }

  // A skipped event is the only one the fold accepts without verifying a signature — it cannot,
  // since it does not know the type's rules — so it must not be allowed to claim a position it did
  // not earn. `p` is already checked above; without this, `g` and `s` were free wire data on an
  // unsigned event, and anything ordering branches by the raw head could be handed
  // `Number.MAX_SAFE_INTEGER` by someone holding no key material at all. Nothing an honest peer
  // appends is at any position but the next one.
  if (event.g !== prior.gen || event.s !== prior.seq + 1) {
    return { status: 'fail', reason: 'sequence gap' }
  }

  // Non-critical: skip, carrying state forward unchanged so positions stay aligned with the input
  // array. `seq` deliberately does not advance — the skipped event established nothing — so a run
  // of consecutive skipped events all claim the same `s`.
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
  // rejects the same log with `invalid inception`. Kept for the same reason — `t` is wire data and
  // this is the check that states what a log must open with — and recorded as unreachable so the
  // next reader does not go looking for the test that elicits it.
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
        // The derivation index, not the event position — the two are the same number for every
        // inception this package builds (`s` is 0), and `keySeq` means the index either way. An
        // inception is self-certifying, so a body carrying any `s` at all is a valid log for the
        // DID it hashes to; writing `s` here would hand such a log a `KeyState` naming a key it
        // never committed, which is the conflation Amendment A removed everywhere else.
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
      return fail(`${CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD}: ${outcome.cap}`, i)
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
        return fail(`${CAPABILITY_REVOKE_NEEDS_VERIFIER}: ${outcome.cap}`, i)
      }
      // The fold is total by contract, and a verifier is caller-supplied code that TypeScript
      // cannot police across a package boundary or a stale build. Both ways it can break that
      // contract are handled here: throwing, and answering with the wrong shape — the previous
      // `null`/key-object contract, or a rejection carrying no reason. Each must come back as a
      // `FoldResult` with a real reason, never as an exception escaping the loop and never as a
      // `reason` of `undefined`, which is a failure a caller can neither log nor match on.
      //
      // Our own adapter documents that it never throws; a third party's need not, and a throw is
      // not evidence that the capability authorises anything.
      let authorisation: CapabilityAuthorisation
      try {
        authorisation = await options.verifyCapability(
          outcome.cap,
          did,
          outcome.target,
          // A copy: `states` keeps growing as the fold proceeds, and this resolver must keep
          // answering for the position it was built at even if the verifier holds on to it.
          createStateResolver(did, [...states]),
        )
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
      // The capability authorises its audience, not its bearer. Checked here rather than left to
      // the verifier so that a verifier which simply forgot cannot make the fold accept a revoke
      // from anyone who read the log — see `CapabilityAuthorisation`.
      if (!verifyEventSignedBy(outcome.signed, authorisation.audienceKey)) {
        return fail(REVOKE_NOT_SIGNED_BY_AUDIENCE, i)
      }
    }
    states.push(outcome.state)
  }

  return { ok: true, states }
}

export function keyStateAt(result: FoldResult, position: number): KeyState | undefined {
  return result.ok ? result.states[position] : undefined
}
