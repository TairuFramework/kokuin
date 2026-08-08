import { digestOf } from './canonical.js'
import {
  type EventCommon,
  type InceptionEvent,
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
  /** Generation at which the current `keys` were established — see Amendment A. */
  keyGen: number
  /** Sequence at which the current `keys` were established — see Amendment A. */
  keySeq: number
  keys: Array<string>
  next: Array<string>
  recovery: string
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

/**
 * Fold a controller's log into per-position key state.
 *
 * `states[i]` is the state *after* `events[i]`, which is what a verifier evaluating at log
 * position `i` must use. That is what makes the deny set position-dependent: clearing a DID at a
 * later position never retroactively validates its earlier actions.
 */
export function foldLog(did: string, events: Array<SignedEvent>): FoldResult {
  if (events.length === 0) {
    return fail('empty log', 0)
  }

  const first = events[0] as SignedEvent<InceptionEvent>
  if (first.event.t !== 'icp') {
    return fail('first event must be an inception', 0)
  }
  if (!verifyInception(first, did)) {
    return fail('invalid inception', 0)
  }

  const states: Array<KeyState> = [
    {
      did,
      gen: first.event.g,
      seq: first.event.s,
      keyGen: first.event.g,
      keySeq: first.event.s,
      keys: first.event.k,
      next: first.event.n,
      recovery: first.event.r,
      deny: new Set<string>(),
      digest: digestOf(first.event),
    },
  ]

  for (let i = 1; i < events.length; i++) {
    const signed = events[i]
    const event = signed.event
    const prior = states[i - 1]

    if (event.i !== did) {
      return fail('event names a different controller', i)
    }

    if (event.t === 'rot') {
      const rot = signed as SignedEvent<RotateEvent>
      const isReset = rot.event.g > prior.gen

      if (isReset) {
        // A reset chains to the inception, not to the head — Amendment A. That is what lets a
        // root holding only its seed author one: `p` is recomputable without the log.
        if (rot.event.s !== 0) {
          return fail('reset must restart the sequence', i)
        }
        if (!verifyReset(rot, first.event)) {
          return fail('invalid reset', i)
        }
      } else {
        if (rot.event.p !== prior.digest) {
          return fail('event does not chain to the previous digest', i)
        }
        if (rot.event.g !== prior.gen || rot.event.s !== prior.seq + 1) {
          return fail('sequence gap', i)
        }
        if (!verifyRotate(rot, { digest: prior.digest, n: prior.next })) {
          return fail('invalid rotate', i)
        }
      }

      states.push({
        did,
        gen: rot.event.g,
        seq: rot.event.s,
        // A rotate (reset included) establishes new keys at its own position.
        keyGen: rot.event.g,
        keySeq: rot.event.s,
        keys: rot.event.k,
        next: rot.event.n,
        recovery: rot.event.r ?? prior.recovery,
        deny: rot.event.d == null ? prior.deny : new Set(rot.event.d),
        digest: digestOf(rot.event),
      })
      continue
    }

    if (event.p !== prior.digest) {
      return fail('event does not chain to the previous digest', i)
    }

    if (event.t === 'rev') {
      const rev = signed as SignedEvent<RevokeEvent>
      if (rev.event.g !== prior.gen || rev.event.s !== prior.seq + 1) {
        return fail('sequence gap', i)
      }
      if (!verifyRevoke(rev, { digest: prior.digest, keys: prior.keys })) {
        return fail('invalid revoke', i)
      }
      const deny = new Set(prior.deny)
      deny.add(rev.event.x)
      // `keyGen`/`keySeq` ride along in the spread: a revoke establishes no key, so the active
      // position is still wherever the last icp/rot put it.
      states.push({ ...prior, seq: rev.event.s, deny, digest: digestOf(rev.event) })
      continue
    }

    return fail(`unknown event type: ${String((event as EventCommon).t)}`, i)
  }

  return { ok: true, states }
}

export function keyStateAt(result: FoldResult, position: number): KeyState | undefined {
  return result.ok ? result.states[position] : undefined
}
