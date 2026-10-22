import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  type EpochLimits,
  type FoldEpochDetail,
  type FoldEpochParams,
  foldEpochDetailed,
  TOO_MANY_FAILED_SIGNATURES,
} from '../src/epoch.js'
import {
  createRemove,
  createRevoke,
  type EpochEvent,
  type EpochSigner,
  type RevokeEvent,
} from '../src/epoch-events.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  type EventCommon,
  type MemberEntry,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { type FoldResult, foldLog, type KeyState } from '../src/fold.js'
import {
  type AuthoritativeLogParams,
  authoritativeLog,
  authoritativeLogWithin,
  createMemoryLogStore,
  LOG_FORKED,
  LOG_NOT_AUTHORITATIVE,
} from '../src/history.js'
import { encodeKey } from '../src/keys.js'
import { MAX_FAILED_SIGNATURES } from '../src/limits.js'
import { type ControllerLog, mergeLogs, pruneLog } from '../src/log.js'

/** {@link foldEpochDetailed}, which these fixtures never drive into the failed-signature refusal. */
function detailOf(params: FoldEpochParams): FoldEpochDetail {
  const detail = foldEpochDetailed(params)
  if (!detail.ok) throw new Error(`epoch fold refused: ${detail.reason}`)
  return detail
}

const seed = new Uint8Array(32).fill(3)
const profile = 0
const context = 'history test'
const icp = createInception(seed, profile)
const did = didFromInception(icp.event)

const memberPrivateKey = new Uint8Array(32).fill(21)
const memberKey = encodeKey(ed25519.getPublicKey(memberPrivateKey), 'EdDSA')
const member: MemberEntry = {
  did: `did:key:${memberKey}`,
  key: memberKey,
  add: digestOf('the add that admitted the member'),
  lease: 1_900_000_000,
}

function settle(prior: EventCommon, deny: Array<string> = []): SignedEvent {
  return createRotate({
    seed,
    profile,
    did,
    prior,
    snapshot: { members: [member], deny },
  })
}

function folded(log: ControllerLog): Extract<FoldResult, { ok: true }> {
  const result = foldLog(did, log)
  if (!result.ok) {
    throw new Error(`fixture does not fold: ${result.reason}`)
  }
  return result
}

const rot = settle(icp.event)
const chain = [icp, rot]
const head = folded({ chain, events: [] }).head

const root: EpochSigner = { root: { seed, profile } }
const asMember: EpochSigner = { member: { privateKey: memberPrivateKey, add: member.add } }

function revoke(
  target: string,
  parents: Array<string> = [head.epoch],
  signer: EpochSigner = root,
  on: KeyState = head,
): SignedEvent<EpochEvent> {
  return createRevoke({ signer, did, head: on, parents, target })
}

/** Under a lowered saturation threshold, so saturation is reachable with a handful of signatures. */
function underLimit({
  limits,
  ...params
}: AuthoritativeLogParams & { limits: Partial<EpochLimits> }) {
  return authoritativeLogWithin(params, limits)
}

const digest = (signed: SignedEvent<EpochEvent>): string => digestOf(signed.event)

const revA = revoke('did:key:zA', [head.epoch], asMember)
const revB = revoke('did:key:zB')
const child = revoke('did:key:zC', [digest(revA), digest(revB)])
const withRevA: ControllerLog = { chain, events: [revA] }
const withRevB: ControllerLog = { chain, events: [revB] }

/**
 * A current-epoch revoke carrying no valid signature. The signature is the wrong length, so the
 * check refuses it before any curve arithmetic: thousands of these stay cheap to fold.
 */
function unsignedRevoke(n: number): SignedEvent<EpochEvent> {
  const event: RevokeEvent = { ...(revB.event as RevokeEvent), x: `did:key:zFlood${n}` }
  return { event, sigs: ['AA'] }
}

function deny(log: ControllerLog): Array<string> {
  return [...folded(log).head.deny].sort()
}

function stored(log: ControllerLog): Array<string> {
  return log.events.map(digest).sort()
}

describe('authoritativeLog()', () => {
  test('a verifier never forgets an event it has seen', async () => {
    const store = createMemoryLogStore()
    await store.merge(
      did,
      async (current) => authoritativeLog({ did, loaded: withRevA, seen: current, context }).log,
    )
    await store.merge(
      did,
      async (current) => authoritativeLog({ did, loaded: withRevB, seen: current, context }).log,
    )
    const log = await store.get(did)
    if (log === undefined) {
      throw new Error('nothing stored')
    }
    expect(deny(log)).toEqual(['did:key:zA', 'did:key:zB'])
  })

  test('the result answers for the union, not for the presentation alone', () => {
    const first = authoritativeLog({ did, loaded: withRevA, seen: undefined, context })
    const { result } = authoritativeLog({ did, loaded: withRevB, seen: first.log, context })
    expect([...result.head.deny].sort()).toEqual(['did:key:zA', 'did:key:zB'])
  })

  test('a pending event is not stored, and applies once presented beside its parents', () => {
    const early = authoritativeLog({
      did,
      loaded: { chain, events: [child] },
      seen: undefined,
      context,
    })
    expect(early.result.pending).toBe(1)
    expect(early.log.events).toHaveLength(0)

    // The parents arrive later, from memory: the child presented again alone now applies.
    const parents = authoritativeLog({
      did,
      loaded: { chain, events: [revA, revB] },
      seen: early.log,
      context,
    })
    const late = authoritativeLog({
      did,
      loaded: { chain, events: [child] },
      seen: parents.log,
      context,
    })
    expect(late.result.pending).toBe(0)
    expect(late.result.head.deny.has('did:key:zC')).toBe(true)
    expect(stored(late.log)).toEqual([revA, revB, child].map(digest).sort())
  })

  test('unsigned epoch events up to the failed-signature limit are neither stored nor saturating', () => {
    const flood = {
      chain,
      events: Array.from({ length: MAX_FAILED_SIGNATURES }, (_, n) => unsignedRevoke(n)),
    }
    const { log, result } = underLimit({
      did,
      loaded: flood,
      seen: undefined,
      context,
      limits: { MAX_EPOCH_EVENTS: 2 },
    })
    expect(log.events).toHaveLength(0)
    expect(result.head.saturated).toBe(false)
    expect(result.rejected).toBe(MAX_FAILED_SIGNATURES)
  })

  test('thousands of unsigned epoch events are refused as a whole', () => {
    const flood = { chain, events: Array.from({ length: 5000 }, (_, n) => unsignedRevoke(n)) }
    expect(() =>
      underLimit({ did, loaded: flood, seen: undefined, context, limits: { MAX_EPOCH_EVENTS: 2 } }),
    ).toThrow(TOO_MANY_FAILED_SIGNATURES)
  })

  test('a forged event riding along with a valid one is dropped, the valid one kept', () => {
    const loaded = { chain, events: [unsignedRevoke(0), revA, { junk: true }] as Array<never> }
    const { log } = authoritativeLog({ did, loaded, seen: undefined, context })
    expect(log.events).toEqual([revA])
  })

  test('a forged copy of a genuine event never displaces the genuine signature', () => {
    const forged = { event: revA.event, sigs: [revB.sigs[0] as string] }
    for (const events of [
      [forged, revA],
      [revA, forged],
    ]) {
      const { log } = authoritativeLog({ did, loaded: { chain, events }, seen: undefined, context })
      expect(log.events).toEqual([revA])
    }
    // CONTROL — the forged copy alone is not the event: nothing applies, nothing is stored.
    const alone = authoritativeLog({
      did,
      loaded: { chain, events: [forged] },
      seen: undefined,
      context,
    })
    expect(alone.log.events).toHaveLength(0)
  })

  test('the copy remembered is the one the fold verified, even once its signer is removed', () => {
    // A member's revoke and root's removal of that member, concurrent: the revoke stands (its causal
    // past holds the member), and the head no longer counts the member. Memory must still keep the
    // member's genuine copy of the revoke, not a forged one presented beside it, and not neither.
    const removal = createRemove({
      signer: root,
      did,
      head,
      parents: [head.epoch],
      add: member.add,
    })
    const forged = { event: revA.event, sigs: [revB.sigs[0] as string] }
    for (const events of [
      [forged, revA, removal],
      [removal, revA, forged],
    ]) {
      const { log, result } = authoritativeLog({
        did,
        loaded: { chain, events },
        seen: undefined,
        context,
      })
      expect(result.head.members.get(member.add)?.effective).toBe(false)
      expect(result.head.deny.has('did:key:zA')).toBe(true)
      expect(stored(log)).toEqual([revA, removal].map(digest).sort())
      expect(log.events.find((entry) => digest(entry) === digest(revA))?.sigs).toEqual(revA.sigs)
    }
  })

  test('saturation persists when a later presentation carries only a subset', () => {
    const limits = { MAX_EPOCH_EVENTS: 2 }
    const all = [revA, revB, child, revoke('did:key:zD')]
    const first = underLimit({
      did,
      loaded: { chain, events: all },
      seen: undefined,
      context,
      limits,
    })
    expect(first.result.head.saturated).toBe(true)
    // Enough to stay saturated, never more: the first MAX_EPOCH_EVENTS + 1 applied events.
    expect(first.log.events).toHaveLength(3)
    expect(stored(first.log)).toEqual(first.result.applied.slice(0, 3).sort())
    // Ancestor-closed: every stored event's parents are the epoch or stored too.
    const kept = new Set(first.log.events.map(digest))
    for (const { event } of first.log.events) {
      expect(event.p.every((parent) => parent === head.epoch || kept.has(parent))).toBe(true)
    }

    const later = underLimit({ did, loaded: withRevA, seen: first.log, context, limits })
    expect(later.result.head.saturated).toBe(true)
    // CONTROL — the subset on its own does not saturate: memory is what keeps the refusal.
    expect(
      underLimit({ did, loaded: withRevA, seen: undefined, context, limits }).result.head.saturated,
    ).toBe(false)
  })

  test('concurrent merges for one DID never lose an event', async () => {
    const store = createMemoryLogStore()
    const merge = (loaded: ControllerLog) =>
      store.merge(did, async (current) => {
        // Yield inside the update, so an unserialised store would interleave the read and the write.
        await Promise.resolve()
        return authoritativeLog({ did, loaded, seen: current, context }).log
      })
    await Promise.all([merge(withRevA), merge(withRevB)])
    const log = await store.get(did)
    if (log === undefined) {
      throw new Error('nothing stored')
    }
    expect(deny(log)).toEqual(['did:key:zA', 'did:key:zB'])
  })

  test('a failed update leaves the stored log alone and does not wedge the next merge', async () => {
    const store = createMemoryLogStore()
    await store.merge(did, async () => withRevA)
    await expect(
      store.merge(did, async () => {
        throw new Error('refused')
      }),
    ).rejects.toThrow('refused')
    expect(await store.get(did)).toEqual(withRevA)
    await store.merge(did, async () => withRevB)
    expect(await store.get(did)).toEqual(withRevB)
  })

  test('a truncated chain is refused once the longer one has been seen', () => {
    const later = settle(rot.event, ['did:key:zLater'])
    const seen = authoritativeLog({
      did,
      loaded: { chain: [icp, rot, later], events: [] },
      seen: undefined,
      context,
    }).log
    expect(() => authoritativeLog({ did, loaded: withRevA, seen, context })).toThrow(
      LOG_NOT_AUTHORITATIVE,
    )
  })

  test('a forked chain is refused', () => {
    const seen = { chain: [icp, rot, settle(rot.event, ['did:key:zOne'])], events: [] }
    const loaded = { chain: [icp, rot, settle(rot.event, ['did:key:zTwo'])], events: [] }
    expect(() => authoritativeLog({ did, loaded, seen, context })).toThrow(LOG_FORKED)
  })

  test('a stored log that no longer folds is no memory', () => {
    const corrupt = { chain: [icp, { ...rot, sigs: ['AA'] }], events: [revA] }
    const { log } = authoritativeLog({ did, loaded: withRevB, seen: corrupt, context })
    expect(log).toEqual(withRevB)
  })

  test('a settlement drops a flood: the next epoch folds without ingesting the old one', () => {
    const limits = { MAX_EPOCH_EVENTS: 2 }
    const flooded = underLimit({
      did,
      loaded: { chain, events: [revA, revB, child] },
      seen: undefined,
      context,
      limits,
    })
    expect(flooded.result.head.saturated).toBe(true)

    // Root settles, carrying what it chooses, and the next epoch starts.
    const settled = settle(rot.event, ['did:key:zA'])
    const nextHead = folded({ chain: [icp, rot, settled], events: [] }).head
    const next = revoke('did:key:zNext', [nextHead.epoch], root, nextHead)
    const loaded = { chain: [icp, rot, settled], events: [next] }
    const { log, result } = underLimit({ did, loaded, seen: flooded.log, context, limits })
    expect(result.head.saturated).toBe(false)
    expect([...result.head.deny].sort()).toEqual(['did:key:zA', 'did:key:zNext'])
    // The old epoch is gone from memory at the settlement: what is held is the new epoch alone, already
    // as small as pruning would make it.
    expect(flooded.log.events).toHaveLength(limits.MAX_EPOCH_EVENTS + 1)
    expect(log.events).toEqual([next])
    expect(pruneLog(did, log)).toEqual(log)
    expect(deny(loaded)).toEqual(deny(log))

    // Dropping the old epoch is not forgetting the current one: a presentation withholding `next`
    // still answers with it, and memory keeps it.
    const withheld = underLimit({
      did,
      loaded: { chain: loaded.chain, events: [] },
      seen: log,
      context,
      limits,
    })
    expect(withheld.result.head.deny.has('did:key:zNext')).toBe(true)
    expect(withheld.log.events).toEqual([next])
  })

  test('memory holds one epoch: saturating epoch after epoch never grows it', () => {
    const limits = { MAX_EPOCH_EVENTS: 2 }
    let seen: ControllerLog | undefined
    let prior = rot
    let presented = chain
    for (let round = 0; round < 3; round++) {
      const on = folded({ chain: presented, events: [] }).head
      const events = ['zW', 'zX', 'zY', 'zZ'].map((name) =>
        revoke(`did:key:${name}${round}`, [on.epoch], root, on),
      )
      const { log, result } = underLimit({
        did,
        loaded: { chain: presented, events },
        seen,
        context,
        limits,
      })
      expect(result.head.saturated).toBe(true)
      expect(log.events).toHaveLength(limits.MAX_EPOCH_EVENTS + 1)
      expect(log.events.every(({ event }) => event.e === on.epoch)).toBe(true)
      seen = log
      const next = settle(prior.event)
      presented = [...presented, next]
      prior = next
    }
  })
})

describe('mergeLogs()', () => {
  test('a chain that extends the other wins, whichever side it is on', () => {
    const longer = { chain: [icp, rot, settle(rot.event)], events: [] }
    const shorter = { chain: [icp, rot], events: [] }
    expect(mergeLogs(did, shorter, longer).chain).toEqual(longer.chain)
    expect(mergeLogs(did, longer, shorter).chain).toEqual(longer.chain)
  })

  test('events are a union, deduplicated by digest', () => {
    const merged = mergeLogs(did, { chain, events: [revA, revB] }, { chain, events: [revB, child] })
    expect(stored(merged)).toEqual([revA, revB, child].map(digest).sort())
  })

  test('a pending event applies once merged with the log carrying its parent', () => {
    const early = { chain, events: [child] }
    expect(folded(early).pending).toBe(1)
    const merged = mergeLogs(did, early, { chain, events: [revA, revB] })
    expect(folded(merged).pending).toBe(0)
    expect(folded(merged).head.deny.has('did:key:zC')).toBe(true)
  })

  test('a forged copy merged first does not shadow the genuine one', () => {
    const forged = { event: revA.event, sigs: [revB.sigs[0] as string] }
    const merged = mergeLogs(did, { chain, events: [forged] }, withRevA)
    expect(folded(merged).head.deny.has('did:key:zA')).toBe(true)
  })

  test('a fork does not merge', () => {
    const one = { chain: [icp, rot, settle(rot.event, ['did:key:zOne'])], events: [] }
    const two = { chain: [icp, rot, settle(rot.event, ['did:key:zTwo'])], events: [] }
    expect(() => mergeLogs(did, one, two)).toThrow(LOG_FORKED)
  })

  test('a higher-generation reset wins over a longer lower generation', () => {
    const reset = createReset(seed, profile, 1)
    const lower = { chain: [icp, rot, settle(rot.event)], events: [revA] }
    const higher = { chain: [icp, reset], events: [] }
    expect(mergeLogs(did, lower, higher).chain).toEqual(higher.chain)
    expect(mergeLogs(did, higher, lower).chain).toEqual(higher.chain)
  })
})

describe('the copy the fold verifies', () => {
  // A two-key root anchor, so a genuine root copy carries two signatures. Joined with a comma they make
  // one string a relay can present as a single forged signature; any lossy key for a signature list
  // would treat that forgery and the genuine copy as one, and judging the forgery first would refuse
  // the event.
  const secondKey = new Uint8Array(32).fill(31)
  const anchor = {
    ...head,
    keys: [...head.keys, encodeKey(ed25519.getPublicKey(secondKey), 'EdDSA')],
  }
  const once = revoke('did:key:zTwoKeys')
  const genuine = { event: once.event, sigs: [...once.sigs, ...signEvent(once.event, [secondKey])] }
  const joined = { event: once.event, sigs: [genuine.sigs.join(',')] }

  test('a forgery spelling the genuine signatures as one string never shadows them', () => {
    for (const events of [
      [joined, genuine],
      [genuine, joined],
    ]) {
      const folded = detailOf({ did, chainStates: [anchor], events })
      expect(folded.applied).toEqual([digest(once)])
      expect(folded.rejected).toBe(0)
      // The copy reported, and so remembered, is the genuine one in either order.
      expect(folded.authentic.get(digest(once))?.sigs).toEqual(genuine.sigs)
    }
  })

  test('CONTROL — the joined forgery alone is refused', () => {
    const folded = detailOf({ did, chainStates: [anchor], events: [joined] })
    expect(folded.applied).toEqual([])
    expect(folded.rejected).toBe(1)
  })
})

describe('a reset re-parented onto a different prefix', () => {
  // The verifier appended the reset to the generation-0 chain it held; a pruned peer carries the same
  // reset straight after the inception and further. One history, whichever side holds which.
  const reset = createReset(seed, profile, 1)
  const appended = { chain: [icp, rot, reset], events: [] }
  const carried = {
    chain: [
      icp,
      reset,
      createRotate({
        seed,
        profile,
        did,
        prior: reset.event,
        snapshot: { members: [], deny: [] },
      }),
    ],
    events: [],
  }

  test('mergeLogs keeps the history carried further, in either order', () => {
    expect(mergeLogs(did, appended, carried).chain).toEqual(carried.chain)
    expect(mergeLogs(did, carried, appended).chain).toEqual(carried.chain)
  })

  test('authoritativeLog accepts it carried further and refuses it served behind', () => {
    expect(authoritativeLog({ did, loaded: carried, seen: appended, context }).log.chain).toEqual(
      carried.chain,
    )
    expect(() => authoritativeLog({ did, loaded: appended, seen: carried, context })).toThrow(
      LOG_NOT_AUTHORITATIVE,
    )
  })
})

describe('pruneLog()', () => {
  test('a pruned and a full store fold to the same head', () => {
    // Generation 0 with an epoch of its own, a reset, then a settled generation 1 with live events.
    const oldEvent = revA
    const reset = createReset(seed, profile, 1, { members: [member], deny: ['did:key:zCarried'] })
    const resetHead = folded({ chain: [icp, rot, settle(rot.event), reset], events: [] }).head
    const genOneRot = createRotate({
      seed,
      profile,
      did,
      prior: reset.event,
      snapshot: { members: [member], deny: ['did:key:zCarried'] },
    })
    const fullChain = [icp, rot, settle(rot.event), reset, genOneRot]
    const liveHead = folded({ chain: fullChain, events: [] }).head
    expect(liveHead.gen).toBe(1)
    const live = revoke('did:key:zLive', [liveHead.epoch], root, liveHead)
    const liveMember = revoke('did:key:zLiveMember', [liveHead.epoch], asMember, liveHead)
    const stale = revoke('did:key:zStale', [resetHead.epoch], root, resetHead)
    const full = {
      chain: fullChain,
      events: [oldEvent, stale, live, liveMember, unsignedRevoke(1)],
    }

    const pruned = pruneLog(did, full)
    expect(pruned.chain).toEqual([icp, reset, genOneRot])
    expect(stored(pruned)).toEqual([live, liveMember].map(digest).sort())

    const a = folded(full)
    const b = folded(pruned)
    expect(b.head).toEqual(a.head)
    expect(b.applied).toEqual(a.applied)
  })

  test('generation 0 keeps its whole chain', () => {
    const longer = [icp, rot, settle(rot.event)]
    expect(pruneLog(did, { chain: longer, events: [] }).chain).toEqual(longer)
  })
})
