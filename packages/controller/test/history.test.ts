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
async function detailOf(params: FoldEpochParams): Promise<FoldEpochDetail> {
  const detail = await foldEpochDetailed(params)
  if (!detail.ok) throw new Error(`epoch fold refused: ${detail.reason}`)
  return detail
}

const seed = new Uint8Array(32).fill(3)
const profile = 0
const context = 'history test'
const icp = await createInception(seed, profile)
const did = didFromInception(icp.event)

const memberPrivateKey = new Uint8Array(32).fill(21)
const memberKey = encodeKey(ed25519.getPublicKey(memberPrivateKey), 'EdDSA')
const member: MemberEntry = {
  did: `did:key:${memberKey}`,
  key: memberKey,
  add: digestOf('the add that admitted the member'),
  lease: 1_900_000_000,
}

async function settle(prior: EventCommon, deny: Array<string> = []): Promise<SignedEvent> {
  return await createRotate({
    seed,
    profile,
    did,
    prior,
    snapshot: { members: [member], deny },
  })
}

async function folded(log: ControllerLog): Promise<Extract<FoldResult, { ok: true }>> {
  const result = await foldLog(did, log)
  if (!result.ok) {
    throw new Error(`fixture does not fold: ${result.reason}`)
  }
  return result
}

const rot = await settle(icp.event)
const chain = [icp, rot]
const head = (await folded({ chain, events: [] })).head

const root: EpochSigner = { root: { seed, profile } }
const asMember: EpochSigner = { member: { privateKey: memberPrivateKey, add: member.add } }

async function revoke(
  target: string,
  parents: Array<string> = [head.epoch],
  signer: EpochSigner = root,
  on: KeyState = head,
): Promise<SignedEvent<EpochEvent>> {
  return await createRevoke({ signer, did, head: on, parents, target })
}

/** Under a lowered saturation threshold, so saturation is reachable with a handful of signatures. */
async function underLimit({
  limits,
  ...params
}: AuthoritativeLogParams & { limits: Partial<EpochLimits> }) {
  return await authoritativeLogWithin(params, limits)
}

const digest = (signed: SignedEvent<EpochEvent>): string => digestOf(signed.event)

const revA = await revoke('did:key:zA', [head.epoch], asMember)
const revB = await revoke('did:key:zB')
const child = await revoke('did:key:zC', [digest(revA), digest(revB)])
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

async function deny(log: ControllerLog): Promise<Array<string>> {
  return [...(await folded(log)).head.deny].sort()
}

function stored(log: ControllerLog): Array<string> {
  return log.events.map(digest).sort()
}

describe('authoritativeLog()', () => {
  test('a verifier never forgets an event it has seen', async () => {
    const store = createMemoryLogStore()
    await store.merge(
      did,
      async (current) =>
        (await authoritativeLog({ did, loaded: withRevA, seen: current, context })).log,
    )
    await store.merge(
      did,
      async (current) =>
        (await authoritativeLog({ did, loaded: withRevB, seen: current, context })).log,
    )
    const log = await store.get(did)
    if (log === undefined) {
      throw new Error('nothing stored')
    }
    expect(await deny(log)).toEqual(['did:key:zA', 'did:key:zB'])
  })

  test('the result answers for the union, not for the presentation alone', async () => {
    const first = await authoritativeLog({ did, loaded: withRevA, seen: undefined, context })
    const { result } = await authoritativeLog({ did, loaded: withRevB, seen: first.log, context })
    expect([...result.head.deny].sort()).toEqual(['did:key:zA', 'did:key:zB'])
  })

  test('a pending event is not stored, and applies once presented beside its parents', async () => {
    const early = await authoritativeLog({
      did,
      loaded: { chain, events: [child] },
      seen: undefined,
      context,
    })
    expect(early.result.pending).toBe(1)
    expect(early.log.events).toHaveLength(0)

    // The parents arrive later, from memory: the child presented again alone now applies.
    const parents = await authoritativeLog({
      did,
      loaded: { chain, events: [revA, revB] },
      seen: early.log,
      context,
    })
    const late = await authoritativeLog({
      did,
      loaded: { chain, events: [child] },
      seen: parents.log,
      context,
    })
    expect(late.result.pending).toBe(0)
    expect(late.result.head.deny.has('did:key:zC')).toBe(true)
    expect(stored(late.log)).toEqual([revA, revB, child].map(digest).sort())
  })

  test('unsigned epoch events up to the failed-signature limit are neither stored nor saturating', async () => {
    const flood = {
      chain,
      events: Array.from({ length: MAX_FAILED_SIGNATURES }, (_, n) => unsignedRevoke(n)),
    }
    const { log, result } = await underLimit({
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

  test('thousands of unsigned epoch events are refused as a whole', async () => {
    const flood = { chain, events: Array.from({ length: 5000 }, (_, n) => unsignedRevoke(n)) }
    await expect(
      async () =>
        await underLimit({
          did,
          loaded: flood,
          seen: undefined,
          context,
          limits: { MAX_EPOCH_EVENTS: 2 },
        }),
    ).rejects.toThrow(TOO_MANY_FAILED_SIGNATURES)
  })

  test('a forged event riding along with a valid one is dropped, the valid one kept', async () => {
    const loaded = { chain, events: [unsignedRevoke(0), revA, { junk: true }] as Array<never> }
    const { log } = await authoritativeLog({ did, loaded, seen: undefined, context })
    expect(log.events).toEqual([revA])
  })

  test('a forged copy of a genuine event never displaces the genuine signature', async () => {
    const forged = { event: revA.event, sigs: [revB.sigs[0] as string] }
    for (const events of [
      [forged, revA],
      [revA, forged],
    ]) {
      const { log } = await authoritativeLog({
        did,
        loaded: { chain, events },
        seen: undefined,
        context,
      })
      expect(log.events).toEqual([revA])
    }
    // CONTROL — the forged copy alone is not the event: nothing applies, nothing is stored.
    const alone = await authoritativeLog({
      did,
      loaded: { chain, events: [forged] },
      seen: undefined,
      context,
    })
    expect(alone.log.events).toHaveLength(0)
  })

  test('the copy remembered is the one the fold verified, even once its signer is removed', async () => {
    // A member's revoke and root's removal of that member, concurrent: the revoke stands (its causal
    // past holds the member), and the head no longer counts the member. Memory must still keep the
    // member's genuine copy of the revoke, not a forged one presented beside it, and not neither.
    const removal = await createRemove({
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
      const { log, result } = await authoritativeLog({
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

  test('saturation persists when a later presentation carries only a subset', async () => {
    const limits = { MAX_EPOCH_EVENTS: 2 }
    const all = [revA, revB, child, await revoke('did:key:zD')]
    const first = await underLimit({
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

    const later = await underLimit({ did, loaded: withRevA, seen: first.log, context, limits })
    expect(later.result.head.saturated).toBe(true)
    // CONTROL — the subset on its own does not saturate: memory is what keeps the refusal.
    expect(
      (await underLimit({ did, loaded: withRevA, seen: undefined, context, limits })).result.head
        .saturated,
    ).toBe(false)
  })

  test('concurrent merges for one DID never lose an event', async () => {
    const store = createMemoryLogStore()
    const merge = (loaded: ControllerLog) =>
      store.merge(did, async (current) => {
        // Yield inside the update, so an unserialised store would interleave the read and the write.
        await Promise.resolve()
        return (await authoritativeLog({ did, loaded, seen: current, context })).log
      })
    await Promise.all([merge(withRevA), merge(withRevB)])
    const log = await store.get(did)
    if (log === undefined) {
      throw new Error('nothing stored')
    }
    expect(await deny(log)).toEqual(['did:key:zA', 'did:key:zB'])
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

  test('a truncated chain is refused once the longer one has been seen', async () => {
    const later = await settle(rot.event, ['did:key:zLater'])
    const seen = (
      await authoritativeLog({
        did,
        loaded: { chain: [icp, rot, later], events: [] },
        seen: undefined,
        context,
      })
    ).log
    await expect(
      async () => await authoritativeLog({ did, loaded: withRevA, seen, context }),
    ).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
  })

  test('a forked chain is refused', async () => {
    const seen = { chain: [icp, rot, await settle(rot.event, ['did:key:zOne'])], events: [] }
    const loaded = { chain: [icp, rot, await settle(rot.event, ['did:key:zTwo'])], events: [] }
    await expect(
      async () => await authoritativeLog({ did, loaded, seen, context }),
    ).rejects.toThrow(LOG_FORKED)
  })

  test('a stored log that no longer folds is no memory', async () => {
    const corrupt = { chain: [icp, { ...rot, sigs: ['AA'] }], events: [revA] }
    const { log } = await authoritativeLog({ did, loaded: withRevB, seen: corrupt, context })
    expect(log).toEqual(withRevB)
  })

  test('a settlement drops a flood: the next epoch folds without ingesting the old one', async () => {
    const limits = { MAX_EPOCH_EVENTS: 2 }
    const flooded = await underLimit({
      did,
      loaded: { chain, events: [revA, revB, child] },
      seen: undefined,
      context,
      limits,
    })
    expect(flooded.result.head.saturated).toBe(true)

    // Root settles, carrying what it chooses, and the next epoch starts.
    const settled = await settle(rot.event, ['did:key:zA'])
    const nextHead = (await folded({ chain: [icp, rot, settled], events: [] })).head
    const next = await revoke('did:key:zNext', [nextHead.epoch], root, nextHead)
    const loaded = { chain: [icp, rot, settled], events: [next] }
    const { log, result } = await underLimit({ did, loaded, seen: flooded.log, context, limits })
    expect(result.head.saturated).toBe(false)
    expect([...result.head.deny].sort()).toEqual(['did:key:zA', 'did:key:zNext'])
    // The old epoch is gone from memory at the settlement: what is held is the new epoch alone, already
    // as small as pruning would make it.
    expect(flooded.log.events).toHaveLength(limits.MAX_EPOCH_EVENTS + 1)
    expect(log.events).toEqual([next])
    expect(await pruneLog(did, log)).toEqual(log)
    expect(await deny(loaded)).toEqual(await deny(log))

    // Dropping the old epoch is not forgetting the current one: a presentation withholding `next`
    // still answers with it, and memory keeps it.
    const withheld = await underLimit({
      did,
      loaded: { chain: loaded.chain, events: [] },
      seen: log,
      context,
      limits,
    })
    expect(withheld.result.head.deny.has('did:key:zNext')).toBe(true)
    expect(withheld.log.events).toEqual([next])
  })

  test('memory holds one epoch: saturating epoch after epoch never grows it', async () => {
    const limits = { MAX_EPOCH_EVENTS: 2 }
    let seen: ControllerLog | undefined
    let prior = rot
    let presented = chain
    for (let round = 0; round < 3; round++) {
      const on = (await folded({ chain: presented, events: [] })).head
      const events = await Promise.all(
        ['zW', 'zX', 'zY', 'zZ'].map(
          async (name) => await revoke(`did:key:${name}${round}`, [on.epoch], root, on),
        ),
      )
      const { log, result } = await underLimit({
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
      const next = await settle(prior.event)
      presented = [...presented, next]
      prior = next
    }
  })
})

describe('mergeLogs()', () => {
  test('a chain that extends the other wins, whichever side it is on', async () => {
    const longer = { chain: [icp, rot, await settle(rot.event)], events: [] }
    const shorter = { chain: [icp, rot], events: [] }
    expect((await mergeLogs(did, shorter, longer)).chain).toEqual(longer.chain)
    expect((await mergeLogs(did, longer, shorter)).chain).toEqual(longer.chain)
  })

  test('events are a union, deduplicated by digest', async () => {
    const merged = await mergeLogs(
      did,
      { chain, events: [revA, revB] },
      { chain, events: [revB, child] },
    )
    expect(stored(merged)).toEqual([revA, revB, child].map(digest).sort())
  })

  test('a pending event applies once merged with the log carrying its parent', async () => {
    const early = { chain, events: [child] }
    expect((await folded(early)).pending).toBe(1)
    const merged = await mergeLogs(did, early, { chain, events: [revA, revB] })
    expect((await folded(merged)).pending).toBe(0)
    expect((await folded(merged)).head.deny.has('did:key:zC')).toBe(true)
  })

  test('a forged copy merged first does not shadow the genuine one', async () => {
    const forged = { event: revA.event, sigs: [revB.sigs[0] as string] }
    const merged = await mergeLogs(did, { chain, events: [forged] }, withRevA)
    expect((await folded(merged)).head.deny.has('did:key:zA')).toBe(true)
  })

  test('a fork does not merge', async () => {
    const one = { chain: [icp, rot, await settle(rot.event, ['did:key:zOne'])], events: [] }
    const two = { chain: [icp, rot, await settle(rot.event, ['did:key:zTwo'])], events: [] }
    await expect(async () => await mergeLogs(did, one, two)).rejects.toThrow(LOG_FORKED)
  })

  test('a higher-generation reset wins over a longer lower generation', async () => {
    const reset = await createReset(seed, profile, 1)
    const lower = { chain: [icp, rot, await settle(rot.event)], events: [revA] }
    const higher = { chain: [icp, reset], events: [] }
    expect((await mergeLogs(did, lower, higher)).chain).toEqual(higher.chain)
    expect((await mergeLogs(did, higher, lower)).chain).toEqual(higher.chain)
  })
})

describe('the copy the fold verifies', async () => {
  // A two-key root anchor, so a genuine root copy carries two signatures. Joined with a comma they make
  // one string a relay can present as a single forged signature; any lossy key for a signature list
  // would treat that forgery and the genuine copy as one, and judging the forgery first would refuse
  // the event.
  const secondKey = new Uint8Array(32).fill(31)
  const anchor = {
    ...head,
    keys: [...head.keys, encodeKey(ed25519.getPublicKey(secondKey), 'EdDSA')],
  }
  const once = await revoke('did:key:zTwoKeys')
  const genuine = {
    event: once.event,
    sigs: [...once.sigs, ...(await signEvent(once.event, [secondKey]))],
  }
  const joined = { event: once.event, sigs: [genuine.sigs.join(',')] }

  test('a forgery spelling the genuine signatures as one string never shadows them', async () => {
    for (const events of [
      [joined, genuine],
      [genuine, joined],
    ]) {
      const folded = await detailOf({ did, chainStates: [anchor], events })
      expect(folded.applied).toEqual([digest(once)])
      expect(folded.rejected).toBe(0)
      // The copy reported, and so remembered, is the genuine one in either order.
      expect(folded.authentic.get(digest(once))?.sigs).toEqual(genuine.sigs)
    }
  })

  test('CONTROL — the joined forgery alone is refused', async () => {
    const folded = await detailOf({ did, chainStates: [anchor], events: [joined] })
    expect(folded.applied).toEqual([])
    expect(folded.rejected).toBe(1)
  })
})

describe('a reset re-parented onto a different prefix', async () => {
  // The verifier appended the reset to the generation-0 chain it held; a pruned peer carries the same
  // reset straight after the inception and further. One history, whichever side holds which.
  const reset = await createReset(seed, profile, 1)
  const appended = { chain: [icp, rot, reset], events: [] }
  const carried = {
    chain: [
      icp,
      reset,
      await createRotate({
        seed,
        profile,
        did,
        prior: reset.event,
        snapshot: { members: [], deny: [] },
      }),
    ],
    events: [],
  }

  test('mergeLogs keeps the history carried further, in either order', async () => {
    expect((await mergeLogs(did, appended, carried)).chain).toEqual(carried.chain)
    expect((await mergeLogs(did, carried, appended)).chain).toEqual(carried.chain)
  })

  test('authoritativeLog accepts it carried further and refuses it served behind', async () => {
    expect(
      (await authoritativeLog({ did, loaded: carried, seen: appended, context })).log.chain,
    ).toEqual(carried.chain)
    await expect(
      async () => await authoritativeLog({ did, loaded: appended, seen: carried, context }),
    ).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
  })
})

describe('pruneLog()', () => {
  test('a pruned and a full store fold to the same head', async () => {
    // Generation 0 with an epoch of its own, a reset, then a settled generation 1 with live events.
    const oldEvent = revA
    const reset = await createReset(seed, profile, 1, {
      members: [member],
      deny: ['did:key:zCarried'],
    })
    const resetHead = (
      await folded({ chain: [icp, rot, await settle(rot.event), reset], events: [] })
    ).head
    const genOneRot = await createRotate({
      seed,
      profile,
      did,
      prior: reset.event,
      snapshot: { members: [member], deny: ['did:key:zCarried'] },
    })
    const fullChain = [icp, rot, await settle(rot.event), reset, genOneRot]
    const liveHead = (await folded({ chain: fullChain, events: [] })).head
    expect(liveHead.gen).toBe(1)
    const live = await revoke('did:key:zLive', [liveHead.epoch], root, liveHead)
    const liveMember = await revoke('did:key:zLiveMember', [liveHead.epoch], asMember, liveHead)
    const stale = await revoke('did:key:zStale', [resetHead.epoch], root, resetHead)
    const full = {
      chain: fullChain,
      events: [oldEvent, stale, live, liveMember, unsignedRevoke(1)],
    }

    const pruned = await pruneLog(did, full)
    expect(pruned.chain).toEqual([icp, reset, genOneRot])
    expect(stored(pruned)).toEqual([live, liveMember].map(digest).sort())

    const a = await folded(full)
    const b = await folded(pruned)
    expect(b.head).toEqual(a.head)
    expect(b.applied).toEqual(a.applied)
  })

  test('generation 0 keeps its whole chain', async () => {
    const longer = [icp, rot, await settle(rot.event)]
    expect((await pruneLog(did, { chain: longer, events: [] })).chain).toEqual(longer)
  })
})
