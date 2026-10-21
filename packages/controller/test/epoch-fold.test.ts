import { ed25519 } from '@noble/curves/ed25519.js'
import { afterEach, describe, expect, test, vi } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { foldEpoch } from '../src/epoch.js'
import {
  createAdd,
  createRemove,
  createRenew,
  createRevoke,
  type EpochEvent,
  type EpochSigner,
} from '../src/epoch-events.js'
import {
  createInception,
  createRotate,
  didFromInception,
  type MemberEntry,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { type FoldResult, foldLog, type KeyState } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'
import { MAX_EPOCH_EVENTS, MAX_LOG_EVENTS } from '../src/limits.js'
import { type ControllerLog, isControllerLog, LOG_TOO_LARGE, MALFORMED_LOG } from '../src/log.js'

const seed = new Uint8Array(32).fill(1)
const profile = 0
const inception = createInception(seed, profile)
const did = didFromInception(inception.event)

/** A member key pair from a fixed secret, so every run builds the same events and digests. */
function memberKeyPair(fill: number): { privateKey: Uint8Array; key: string; did: string } {
  const privateKey = new Uint8Array(32).fill(fill)
  const key = encodeKey(ed25519.getPublicKey(privateKey), 'EdDSA')
  return { privateKey, key, did: `did:key:${key}` }
}

function entryOf(pair: { key: string; did: string }, add: string): MemberEntry {
  return { did: pair.did, key: pair.key, add, lease: 1_900_000_000 }
}

const a = memberKeyPair(11)
const b = memberKeyPair(12)
const memberA = entryOf(a, digestOf('the add that admitted A'))
const memberB = entryOf(b, digestOf('the add that admitted B'))

const rot = createRotate({
  seed,
  profile,
  did,
  prior: inception.event,
  options: { snapshot: { members: [memberA, memberB], deny: [] } },
})
const chain: Array<SignedEvent> = [inception, rot]

function chainFolded(events: Array<SignedEvent>): Extract<FoldResult, { ok: true }> {
  const result = foldLog(did, { chain: events, events: [] })
  if (!result.ok) {
    throw new Error(`fixture chain does not fold: ${result.reason}`)
  }
  return result
}

const head = chainFolded(chain).head
const epoch = head.epoch

const root: EpochSigner = { root: { seed, profile } }
const signerA: EpochSigner = { member: { privateKey: a.privateKey, add: memberA.add } }
const signerB: EpochSigner = { member: { privateKey: b.privateKey, add: memberB.add } }

function revoke(
  signer: EpochSigner,
  target: string,
  parents: Array<string> = [epoch],
  on: KeyState = head,
): SignedEvent<EpochEvent> {
  return createRevoke({ signer, did, head: on, parents, target })
}

function digest(signed: SignedEvent<EpochEvent>): string {
  return digestOf(signed.event)
}

const revA = revoke(signerA, 'did:key:zA')
const revB = revoke(signerB, 'did:key:zB')
const renew = createRenew({
  signer: root,
  did,
  head,
  parents: [epoch],
  add: memberA.add,
  lease: 2_000_000_000,
})
const child = revoke(root, 'did:key:zC', [digest(revA), digest(revB)])

function fold(events: Array<unknown>, presented: Array<SignedEvent> = chain): FoldResult {
  return foldLog(did, { chain: presented, events: events as ControllerLog['events'] })
}

function folded(events: Array<unknown>, presented?: Array<SignedEvent>) {
  const result = fold(events, presented)
  if (!result.ok) {
    throw new Error(`log does not fold: ${result.reason}`)
  }
  return result
}

/** Everything order independence promises about a fold, in a form `toEqual` compares exactly. */
function summary(result: FoldResult) {
  if (!result.ok) {
    return result
  }
  return {
    deny: [...result.head.deny].sort(),
    members: [...result.head.members.entries()].sort(([x], [y]) => (x < y ? -1 : 1)),
    saturated: result.head.saturated,
    applied: result.applied,
    pending: result.pending,
    rejected: result.rejected,
  }
}

function permutations<T>(items: Array<T>): Array<Array<T>> {
  if (items.length <= 1) {
    return [items]
  }
  return items.flatMap((item, i) =>
    permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item, ...rest]),
  )
}

describe('the log shape', () => {
  test('a log is a chain and an event list', () => {
    expect(isControllerLog({ chain, events: [] })).toBe(true)
    expect(isControllerLog({ chain })).toBe(false)
    expect(isControllerLog({ events: [] })).toBe(false)
    expect(isControllerLog({ chain: {}, events: [] })).toBe(false)
    expect(isControllerLog(chain)).toBe(false)
    expect(isControllerLog(null)).toBe(false)
  })

  test('anything else is a malformed log, not a throw', () => {
    for (const log of [undefined, null, 7, 'log', chain, { chain }, { chain, events: 'x' }]) {
      expect(foldLog(did, log as unknown as ControllerLog)).toEqual({
        ok: false,
        reason: MALFORMED_LOG,
        index: 0,
      })
    }
  })

  test('a chain-only log folds to its last chain state', () => {
    const result = folded([])
    expect(result.states).toHaveLength(chain.length)
    expect(result.head).toEqual(result.states.at(-1))
    expect(result).toMatchObject({ applied: [], pending: 0, rejected: 0 })
  })
})

describe('merging an epoch', () => {
  test('two concurrent member revokes merge', () => {
    const result = fold([revA, revB])
    expect(result.ok && [...result.head.deny].sort()).toEqual(['did:key:zA', 'did:key:zB'])
    expect(result.ok && result.applied.length).toBe(2)
  })

  test('the per-chain states are untouched by the epoch', () => {
    const result = folded([revA, revB])
    expect(result.states).toEqual(chainFolded(chain).states)
    expect(result.states.at(-1)?.deny.size).toBe(0)
  })

  test('the head is identical in every presentation order', () => {
    const expected = summary(fold([revA, revB, renew, child]))
    expect(expected).toMatchObject({
      deny: ['did:key:zA', 'did:key:zB', 'did:key:zC'],
      pending: 0,
      rejected: 0,
    })
    for (const order of permutations([revA, revB, renew, child])) {
      expect(summary(fold(order))).toEqual(expected)
    }
  })

  test('applied events are listed parents first, ties by ascending digest', () => {
    const result = folded([child, renew, revB, revA])
    const roots = [digest(revA), digest(revB), digest(renew)].sort()
    expect(result.applied).toEqual([...roots, digest(child)])
  })

  test('an event presented twice applies once', () => {
    const result = folded([revA, revA, { ...revA, event: { ...revA.event } }])
    expect(result.applied).toEqual([digest(revA)])
    expect(result).toMatchObject({ pending: 0, rejected: 0 })
  })

  test('a copy under a forged signature does not shadow the genuine event, in either order', () => {
    const forged = { event: revA.event, sigs: signEvent(revA.event, [b.privateKey]) }
    const expected = summary(fold([revA]))
    expect(summary(fold([forged, revA]))).toEqual(expected)
    expect(summary(fold([revA, forged]))).toEqual(expected)
    // Alone, the forged copy is one rejected event.
    expect(summary(fold([forged]))).toMatchObject({ applied: [], rejected: 1, deny: [] })
  })

  test('an event naming an older epoch has no effect', () => {
    // Built against the inception's epoch; the chain head is the later rotate.
    const atInception = chainFolded([inception]).head
    const stale = revoke(root, 'did:key:zOld', [atInception.epoch], atInception)
    expect(stale.event.e).not.toBe(epoch)
    expect(summary(fold([stale]))).toEqual(summary(fold([])))
  })

  test('an event with a parent from an older epoch is rejected', () => {
    // The older chain event itself as a parent.
    const onChain = revoke(root, 'did:key:zX', [epoch, digestOf(inception.event)])
    expect(summary(fold([onChain]))).toMatchObject({ applied: [], rejected: 1, pending: 0 })
    // An event of the older epoch, presented alongside, as a parent.
    const atInception = chainFolded([inception]).head
    const stale = revoke(root, 'did:key:zOld', [atInception.epoch], atInception)
    const crossing = revoke(root, 'did:key:zY', [epoch, digest(stale)])
    expect(summary(fold([stale, crossing]))).toMatchObject({ applied: [], rejected: 1, pending: 0 })
    // Control: the same event with only same-epoch parents applies.
    expect(summary(fold([revoke(root, 'did:key:zY')]))).toMatchObject({ rejected: 0 })
  })

  test('an event whose parent is missing is pending, not applied', () => {
    const orphan = revoke(root, 'did:key:zX', [digestOf('never presented')])
    expect(summary(fold([orphan]))).toMatchObject({
      applied: [],
      pending: 1,
      rejected: 0,
      deny: [],
    })
    // And once its parent is presented, it applies.
    expect(summary(fold([child]))).toMatchObject({ applied: [], pending: 1 })
    expect(summary(fold([child, revA, revB]))).toMatchObject({ pending: 0, rejected: 0 })
  })

  test('an unsigned or wrongly signed event is rejected and its children stay pending', () => {
    const unsigned = { event: revA.event, sigs: [] }
    const wrong = { event: revA.event, sigs: signEvent(revA.event, [b.privateKey]) }
    for (const bad of [unsigned, wrong]) {
      expect(summary(fold([bad, revB, child]))).toMatchObject({
        applied: [digest(revB)],
        pending: 1,
        rejected: 1,
        deny: ['did:key:zB'],
      })
    }
  })

  test('an event for another controller or generation is rejected', () => {
    const other = { ...revA.event, i: 'did:kokuin:zSomeoneElse' }
    const generation = { ...revA.event, g: 1 }
    for (const event of [other, generation]) {
      const resigned = { event, sigs: signEvent(event, [a.privateKey]) }
      expect(summary(fold([resigned]))).toMatchObject({ applied: [], rejected: 1 })
    }
  })

  test('hostile entries are counted as rejected, never thrown on', () => {
    const hostile = [null, 7, 'x', [], {}, { event: null, sigs: [] }, { event: revA.event }]
    const sparse: Array<unknown> = [revA]
    sparse[3] = revB
    let result: FoldResult | undefined
    expect(() => {
      result = fold([...hostile, ...sparse])
    }).not.toThrow()
    expect(summary(result as FoldResult)).toMatchObject({
      applied: [digest(revA), digest(revB)].sort(),
      rejected: hostile.length + 2,
    })
  })
})

describe('who may sign', () => {
  test('a root revoke may not deny a key the chain head publishes', () => {
    const publishing = [...head.keys, ...head.agreement]
    for (const key of publishing) {
      expect(summary(fold([revoke(root, `#${key}`)]))).toMatchObject({ rejected: 1, deny: [] })
    }
    const retired = `#${inception.event.k[0]}`
    expect(summary(fold([revoke(root, retired)]))).toMatchObject({ rejected: 0, deny: [retired] })
  })

  test('a member event under an unknown add reference is rejected', () => {
    const stranger = revoke({ member: { privateKey: a.privateKey, add: digestOf('nobody') } }, 'x')
    expect(summary(fold([stranger]))).toMatchObject({ applied: [], rejected: 1 })
  })

  test('a member event signed by another member`s key is rejected', () => {
    const borrowed = revoke({ member: { privateKey: b.privateKey, add: memberA.add } }, 'x')
    expect(summary(fold([borrowed]))).toMatchObject({ applied: [], rejected: 1 })
  })

  test('add, renew and remove are root-only', () => {
    const c = memberKeyPair(13)
    const memberAdd = {
      event: {
        ...createAdd({
          seed,
          profile,
          did,
          head,
          parents: [epoch],
          member: { did: c.did, key: c.key, lease: 1_900_000_000 },
        }).event,
        by: memberA.add,
      },
      sigs: [] as Array<string>,
    }
    memberAdd.sigs = signEvent(memberAdd.event, [a.privateKey])
    const memberRenew = createRenew({
      signer: signerA,
      did,
      head,
      parents: [epoch],
      add: memberB.add,
      lease: 2_000_000_000,
    })
    const memberRemove = createRemove({
      signer: signerA,
      did,
      head,
      parents: [epoch],
      add: memberB.add,
    })
    for (const event of [memberAdd, memberRenew, memberRemove]) {
      expect(summary(fold([event]))).toMatchObject({ applied: [], rejected: 1 })
    }
  })

  test('a root add makes a member that can sign in its causal future', () => {
    const c = memberKeyPair(13)
    const add = createAdd({
      seed,
      profile,
      did,
      head,
      parents: [epoch],
      member: { did: c.did, key: c.key, lease: 1_900_000_000 },
    })
    const signerC: EpochSigner = { member: { privateKey: c.privateKey, add: digest(add) } }
    const after = revoke(signerC, 'did:key:zAfter', [digest(add)])
    const concurrent = revoke(signerC, 'did:key:zConcurrent')
    const result = folded([add, after, concurrent])
    expect(result.applied).toEqual(expect.arrayContaining([digest(add), digest(after)]))
    expect(result.rejected).toBe(1)
    expect(result.head.members.get(digest(add))).toMatchObject({ effective: true, removed: false })
  })

  test('a member revoke after the member was removed in its causal past is rejected', () => {
    const removal = createRemove({ signer: root, did, head, parents: [epoch], add: memberA.add })
    const late = revoke(signerA, 'did:key:zLate', [digest(removal)])
    expect(summary(fold([removal, late]))).toMatchObject({
      applied: [digest(removal)],
      rejected: 1,
      deny: [],
    })
  })

  test('a member revoke concurrent with the member being removed still applies', () => {
    const removal = createRemove({ signer: root, did, head, parents: [epoch], add: memberA.add })
    const result = folded([removal, revA])
    expect([...result.head.deny]).toEqual(['did:key:zA'])
    expect(result.head.members.get(memberA.add)).toMatchObject({ removed: true, effective: false })
    expect(result.rejected).toBe(0)
  })

  test('a member denied in its causal past may not sign; concurrently it still may', () => {
    const denial = revoke(root, memberA.did)
    const late = revoke(signerA, 'did:key:zLate', [digest(denial)])
    expect(summary(fold([denial, late]))).toMatchObject({ rejected: 1, deny: [memberA.did] })
    const result = folded([denial, revA])
    expect(result.rejected).toBe(0)
    expect(result.head.members.get(memberA.add)).toMatchObject({ removed: false, effective: false })
  })

  test('a root renew raises the lease in the head', () => {
    const result = folded([renew])
    expect(result.head.members.get(memberA.add)?.lease).toBe(2_000_000_000)
    expect(result.head.members.get(memberB.add)?.lease).toBe(memberB.lease)
  })
})

describe('limits', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  test('more valid events than the saturation threshold saturate the head but the chain still folds', () => {
    const events = [revA, revB, renew]
    const states = chainFolded(chain).states
    const over = foldEpoch({ did, chainStates: states, events, limits: { MAX_EPOCH_EVENTS: 2 } })
    expect(over.head.saturated).toBe(true)
    expect(over.applied).toHaveLength(3)
    const at = foldEpoch({ did, chainStates: states, events, limits: { MAX_EPOCH_EVENTS: 3 } })
    expect(at.head.saturated).toBe(false)
    // Invalid events never count towards saturation.
    const junk = [
      ...events,
      { event: revA.event, sigs: [] },
      revoke(root, 'x', [digestOf('absent')]),
    ]
    expect(
      foldEpoch({ did, chainStates: states, events: junk, limits: { MAX_EPOCH_EVENTS: 3 } }).head
        .saturated,
    ).toBe(false)
  })

  test('more than MAX_EPOCH_EVENTS valid events saturate the head but the chain still folds', () => {
    const events = Array.from({ length: MAX_EPOCH_EVENTS + 1 }, (_, n) =>
      revoke(root, `did:key:zFlood${n}`),
    )
    const result = fold(events)
    expect(result.ok && result.head.saturated).toBe(true)
    expect(result.ok && result.states.length).toBe(chain.length)
  }, 60_000)

  test('more than MAX_LOG_EVENTS entries fail the request with LOG_TOO_LARGE', () => {
    const events = Array.from({ length: MAX_LOG_EVENTS + 1 }, () => null)
    expect(fold(events)).toEqual({ ok: false, reason: LOG_TOO_LARGE, index: -1 })
    expect(fold(events.slice(1)).ok).toBe(true)
  })

  test('a member revoke folds with no clock', () => {
    const log = [revA, revB, renew, child]
    const foldedEarlier = summary(fold(log))
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2100-01-01'))
    expect(summary(fold(log))).toEqual(foldedEarlier)
  })
})
