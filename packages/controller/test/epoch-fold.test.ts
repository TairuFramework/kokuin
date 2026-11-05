import type { MemberState } from '../src/fold.js'

type FoldSummary =
  | { ok: false; reason: string; index: number }
  | {
      deny: Array<string>
      members: Array<[string, MemberState]>
      saturated: boolean
      applied: Array<string>
      pending: number
      rejected: number
    }
type RevokeParams = { signer: EpochSigner; target: string; parents?: Array<string>; on?: KeyState }

import { ed25519 } from '@noble/curves/ed25519.js'
import { afterEach, describe, expect, test, vi } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  ADD_KEY_ALREADY_MEMBER,
  ADD_NOT_ROOT,
  DEFAULT_EPOCH_LIMITS,
  type FoldEpochDetail,
  type FoldEpochParams,
  type FoldEpochResult,
  foldEpoch,
  foldEpochDetailed,
  MEMBER_REVOKES_MEMBER,
  REVOKE_NAMES_ROOT_KEY,
  SELF_REMOVE,
  SELF_RENEW,
  UNKNOWN_MEMBER,
} from '../src/epoch.js'
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

/** {@link foldEpochDetailed}, which these fixtures never drive into the failed-signature refusal. */
async function detailOf(params: FoldEpochParams): Promise<FoldEpochDetail> {
  const detail = await foldEpochDetailed(params)
  if (!detail.ok) throw new Error(`epoch fold refused: ${detail.reason}`)
  return detail
}

/** {@link foldEpoch}, which these fixtures never drive into the failed-signature refusal. */
async function epochOf(params: FoldEpochParams): Promise<FoldEpochResult> {
  const result = await foldEpoch(params)
  if (!result.ok) throw new Error(`epoch fold refused: ${result.reason}`)
  return result
}

const seed = new Uint8Array(32).fill(1)
const profile = 0
const inception = await createInception({ seed, profile })
const did = didFromInception(inception.event)

/** A member key pair from a fixed secret, so every run builds the same events and digests. */
function memberKeyPair(fill: number): { privateKey: Uint8Array; key: string; did: string } {
  const privateKey = new Uint8Array(32).fill(fill)
  const key = encodeKey({ publicKey: ed25519.getPublicKey(privateKey), alg: 'EdDSA' })
  return { privateKey, key, did: `did:key:${key}` }
}

function entryOf(pair: { key: string; did: string }, add: string): MemberEntry {
  return { did: pair.did, key: pair.key, add, lease: 1_900_000_000 }
}

const a = memberKeyPair(11)
const b = memberKeyPair(12)
const memberA = entryOf(a, digestOf('the add that admitted A'))
const memberB = entryOf(b, digestOf('the add that admitted B'))

const rot = await createRotate({
  seed,
  profile,
  did,
  prior: inception.event,
  snapshot: { members: [memberA, memberB], deny: [] },
})
const chain: Array<SignedEvent> = [inception, rot]

async function chainFolded(events: Array<SignedEvent>): Promise<Extract<FoldResult, { ok: true }>> {
  const result = await foldLog({ did, input: { chain: events, events: [] } })
  if (!result.ok) {
    throw new Error(`fixture chain does not fold: ${result.reason}`)
  }
  return result
}

const head = (await chainFolded(chain)).head
const epoch = head.epoch

const root: EpochSigner = { root: { seed, profile } }
const signerA: EpochSigner = { member: { privateKey: a.privateKey, add: memberA.add } }
const signerB: EpochSigner = { member: { privateKey: b.privateKey, add: memberB.add } }

async function revoke({
  signer,
  target,
  parents = [epoch],
  on = head,
}: RevokeParams): Promise<SignedEvent<EpochEvent>> {
  return await createRevoke({ signer, did, head: on, parents, target })
}

function digest(signed: SignedEvent<EpochEvent>): string {
  return digestOf(signed.event)
}

const revA = await revoke({ signer: signerA, target: 'did:key:zA' })
const revB = await revoke({ signer: signerB, target: 'did:key:zB' })
const renew = await createRenew({
  signer: root,
  did,
  head,
  parents: [epoch],
  add: memberA.add,
  lease: 2_000_000_000,
})
const child = await revoke({
  signer: root,
  target: 'did:key:zC',
  parents: [digest(revA), digest(revB)],
})

async function fold(
  events: Array<unknown>,
  presented: Array<SignedEvent> = chain,
): Promise<FoldResult> {
  return await foldLog({
    did,
    input: { chain: presented, events: events as ControllerLog['events'] },
  })
}

async function folded(events: Array<unknown>, presented?: Array<SignedEvent>) {
  const result = await fold(events, presented)
  if (!result.ok) {
    throw new Error(`log does not fold: ${result.reason}`)
  }
  return result
}

/** Everything order independence promises about a fold, in a form `toEqual` compares exactly. */
function summary(result: FoldResult): FoldSummary {
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

function permutations<TValue>(items: Array<TValue>): Array<Array<TValue>> {
  if (items.length <= 1) {
    return [items]
  }
  return items.flatMap((item, i) => {
    return permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => {
      return [item, ...rest]
    })
  })
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

  test('anything else is a malformed log, not a throw', async () => {
    for (const log of [undefined, null, 7, 'log', chain, { chain }, { chain, events: 'x' }]) {
      expect(await foldLog({ did, input: log as unknown as ControllerLog })).toEqual({
        ok: false,
        reason: MALFORMED_LOG,
        index: 0,
      })
    }
  })

  test('a chain-only log folds to its last chain state', async () => {
    const result = await folded([])
    expect(result.states).toHaveLength(chain.length)
    expect(result.head).toEqual(result.states.at(-1))
    expect(result).toMatchObject({ applied: [], pending: 0, rejected: 0 })
  })
})

describe('merging an epoch', () => {
  test('two concurrent member revokes merge', async () => {
    const result = await fold([revA, revB])
    expect(result.ok && [...result.head.deny].sort()).toEqual(['did:key:zA', 'did:key:zB'])
    expect(result.ok && result.applied.length).toBe(2)
  })

  test('the per-chain states are untouched by the epoch', async () => {
    const result = await folded([revA, revB])
    expect(result.states).toEqual((await chainFolded(chain)).states)
    expect(result.states.at(-1)?.deny.size).toBe(0)
  })

  test('the head is identical in every presentation order', async () => {
    const expected = summary(await fold([revA, revB, renew, child]))
    expect(expected).toMatchObject({
      deny: ['did:key:zA', 'did:key:zB', 'did:key:zC'],
      pending: 0,
      rejected: 0,
    })
    for (const order of permutations([revA, revB, renew, child])) {
      expect(summary(await fold(order))).toEqual(expected)
    }
  })

  test('applied events are listed parents first, ties by ascending digest', async () => {
    const result = await folded([child, renew, revB, revA])
    const roots = [digest(revA), digest(revB), digest(renew)].sort()
    expect(result.applied).toEqual([...roots, digest(child)])
  })

  test('an event presented twice applies once', async () => {
    const result = await folded([revA, revA, { ...revA, event: { ...revA.event } }])
    expect(result.applied).toEqual([digest(revA)])
    expect(result).toMatchObject({ pending: 0, rejected: 0 })
  })

  test('a copy under a forged signature does not shadow the genuine event, in either order', async () => {
    const forged = { event: revA.event, sigs: await signEvent(revA.event, [b.privateKey]) }
    const expected = summary(await fold([revA]))
    expect(summary(await fold([forged, revA]))).toEqual(expected)
    expect(summary(await fold([revA, forged]))).toEqual(expected)
    // Alone, the forged copy is one rejected event.
    expect(summary(await fold([forged]))).toMatchObject({ applied: [], rejected: 1, deny: [] })
  })

  test('an event naming an older epoch has no effect', async () => {
    // Built against the inception's epoch; the chain head is the later rotate.
    const atInception = (await chainFolded([inception])).head
    const stale = await revoke({
      signer: root,
      target: 'did:key:zOld',
      parents: [atInception.epoch],
      on: atInception,
    })
    expect(stale.event.e).not.toBe(epoch)
    expect(summary(await fold([stale]))).toEqual(summary(await fold([])))
  })

  test('an event with a parent from an older epoch is rejected', async () => {
    // The older chain event itself as a parent.
    const onChain = await revoke({
      signer: root,
      target: 'did:key:zX',
      parents: [epoch, digestOf(inception.event)],
    })
    expect(summary(await fold([onChain]))).toMatchObject({ applied: [], rejected: 1, pending: 0 })
    // An event of the older epoch, presented alongside, as a parent.
    const atInception = (await chainFolded([inception])).head
    const stale = await revoke({
      signer: root,
      target: 'did:key:zOld',
      parents: [atInception.epoch],
      on: atInception,
    })
    const crossing = await revoke({
      signer: root,
      target: 'did:key:zY',
      parents: [epoch, digest(stale)],
    })
    expect(summary(await fold([stale, crossing]))).toMatchObject({
      applied: [],
      rejected: 1,
      pending: 0,
    })
    // Control: the same event with only same-epoch parents applies.
    expect(
      summary(await fold([await revoke({ signer: root, target: 'did:key:zY' })])),
    ).toMatchObject({ rejected: 0 })
  })

  test('a refused child never takes down the parent it also names', async () => {
    const atInception = (await chainFolded([inception])).head
    const stale = await revoke({
      signer: root,
      target: 'did:key:zOld',
      parents: [atInception.epoch],
      on: atInception,
    })
    const parent = await revoke({ signer: root, target: 'did:key:zP' })
    // Cross-epoch parents of two kinds: a chain event, and an event of an older epoch.
    for (const foreign of [digestOf(inception.event), digest(stale)]) {
      const crossing = await revoke({
        signer: root,
        target: 'did:key:zC',
        parents: [digest(parent), foreign],
      })
      for (const order of permutations([parent, crossing, stale])) {
        expect(summary(await fold(order))).toMatchObject({
          applied: [digest(parent)],
          rejected: 1,
          pending: 0,
          deny: ['did:key:zP'],
        })
      }
    }
  })

  test('an event whose parent is missing is pending, not applied', async () => {
    const orphan = await revoke({
      signer: root,
      target: 'did:key:zX',
      parents: [digestOf('never presented')],
    })
    expect(summary(await fold([orphan]))).toMatchObject({
      applied: [],
      pending: 1,
      rejected: 0,
      deny: [],
    })
    // And once its parent is presented, it applies.
    expect(summary(await fold([child]))).toMatchObject({ applied: [], pending: 1 })
    expect(summary(await fold([child, revA, revB]))).toMatchObject({ pending: 0, rejected: 0 })
  })

  test('an unsigned or wrongly signed event is rejected and its children stay pending', async () => {
    const unsigned = { event: revA.event, sigs: [] }
    const wrong = { event: revA.event, sigs: await signEvent(revA.event, [b.privateKey]) }
    for (const bad of [unsigned, wrong]) {
      expect(summary(await fold([bad, revB, child]))).toMatchObject({
        applied: [digest(revB)],
        pending: 1,
        rejected: 1,
        deny: ['did:key:zB'],
      })
    }
  })

  test('an event for another controller or generation is rejected', async () => {
    const other = { ...revA.event, i: 'did:kokuin:zSomeoneElse' }
    const generation = { ...revA.event, g: 1 }
    for (const event of [other, generation]) {
      const resigned = { event, sigs: await signEvent(event, [a.privateKey]) }
      expect(summary(await fold([resigned]))).toMatchObject({ applied: [], rejected: 1 })
    }
  })

  test('hostile entries are counted as rejected, never thrown on', async () => {
    const hostile = [null, 7, 'x', [], {}, { event: null, sigs: [] }, { event: revA.event }]
    const sparse: Array<unknown> = [revA]
    sparse[3] = revB
    let result: FoldResult | undefined
    await expect(
      (async () => {
        result = await fold([...hostile, ...sparse])
      })(),
    ).resolves.toBeUndefined()
    expect(summary(result as FoldResult)).toMatchObject({
      applied: [digest(revA), digest(revB)].sort(),
      rejected: hostile.length + 2,
    })
  })
})

describe('who may sign', () => {
  test('a root revoke may not deny a key the chain head publishes', async () => {
    const publishing = [...head.keys, ...head.agreement]
    for (const key of publishing) {
      expect(
        summary(await fold([await revoke({ signer: root, target: `#${key}` })])),
      ).toMatchObject({
        rejected: 1,
        deny: [],
      })
    }
    const retired = `#${inception.event.k[0]}`
    expect(summary(await fold([await revoke({ signer: root, target: retired })]))).toMatchObject({
      rejected: 0,
      deny: [retired],
    })
  })

  test('a member event under an unknown add reference is rejected', async () => {
    const stranger = await revoke({
      signer: { member: { privateKey: a.privateKey, add: digestOf('nobody') } },
      target: 'x',
    })
    expect(summary(await fold([stranger]))).toMatchObject({ applied: [], rejected: 1 })
  })

  test('a member event signed by another member`s key is rejected', async () => {
    const borrowed = await revoke({
      signer: { member: { privateKey: b.privateKey, add: memberA.add } },
      target: 'x',
    })
    expect(summary(await fold([borrowed]))).toMatchObject({ applied: [], rejected: 1 })
  })

  test('add is root-only; another member may renew and remove', async () => {
    const c = memberKeyPair(13)
    const memberAdd = {
      event: {
        ...(
          await createAdd({
            seed,
            profile,
            did,
            head,
            parents: [epoch],
            member: { did: c.did, key: c.key, lease: 1_900_000_000 },
          })
        ).event,
        by: memberA.add,
      },
      sigs: [] as Array<string>,
    }
    memberAdd.sigs = await signEvent(memberAdd.event, [a.privateKey])
    const memberRenew = await createRenew({
      signer: signerA,
      did,
      head,
      parents: [epoch],
      add: memberB.add,
      lease: 2_000_000_000,
    })
    const memberRemove = await createRemove({
      signer: signerA,
      did,
      head,
      parents: [epoch],
      add: memberB.add,
    })
    expect(summary(await fold([memberAdd]))).toMatchObject({ applied: [], rejected: 1 })
    for (const event of [memberRenew, memberRemove]) {
      expect(summary(await fold([event]))).toMatchObject({ applied: [digest(event)], rejected: 0 })
    }
  })

  test('a root add makes a member that can sign in its causal future', async () => {
    const c = memberKeyPair(13)
    const add = await createAdd({
      seed,
      profile,
      did,
      head,
      parents: [epoch],
      member: { did: c.did, key: c.key, lease: 1_900_000_000 },
    })
    const signerC: EpochSigner = { member: { privateKey: c.privateKey, add: digest(add) } }
    const after = await revoke({
      signer: signerC,
      target: 'did:key:zAfter',
      parents: [digest(add)],
    })
    const concurrent = await revoke({ signer: signerC, target: 'did:key:zConcurrent' })
    const result = await folded([add, after, concurrent])
    expect(result.applied).toEqual(expect.arrayContaining([digest(add), digest(after)]))
    expect(result.rejected).toBe(1)
    expect(result.head.members.get(digest(add))).toMatchObject({ effective: true, removed: false })
  })

  test('a member revoke after the member was removed in its causal past is rejected', async () => {
    const removal = await createRemove({
      signer: root,
      did,
      head,
      parents: [epoch],
      add: memberA.add,
    })
    const late = await revoke({
      signer: signerA,
      target: 'did:key:zLate',
      parents: [digest(removal)],
    })
    expect(summary(await fold([removal, late]))).toMatchObject({
      applied: [digest(removal)],
      rejected: 1,
      deny: [],
    })
  })

  test('a member revoke concurrent with the member being removed still applies', async () => {
    const removal = await createRemove({
      signer: root,
      did,
      head,
      parents: [epoch],
      add: memberA.add,
    })
    const result = await folded([removal, revA])
    expect([...result.head.deny]).toEqual(['did:key:zA'])
    expect(result.head.members.get(memberA.add)).toMatchObject({ removed: true, effective: false })
    expect(result.rejected).toBe(0)
  })

  test('a member denied in its causal past may not sign; concurrently it still may', async () => {
    const denial = await revoke({ signer: root, target: memberA.did })
    const late = await revoke({
      signer: signerA,
      target: 'did:key:zLate',
      parents: [digest(denial)],
    })
    expect(summary(await fold([denial, late]))).toMatchObject({ rejected: 1, deny: [memberA.did] })
    const result = await folded([denial, revA])
    expect(result.rejected).toBe(0)
    expect(result.head.members.get(memberA.add)).toMatchObject({ removed: false, effective: false })
  })

  test('a root renew raises the lease in the head', async () => {
    const result = await folded([renew])
    expect(result.head.members.get(memberA.add)?.lease).toBe(2_000_000_000)
    expect(result.head.members.get(memberB.add)?.lease).toBe(memberB.lease)
  })
})

describe('limits', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  test('more valid events than the saturation threshold saturate the head but the chain still folds', async () => {
    const events = [revA, revB, renew]
    const states = (await chainFolded(chain)).states
    const over = await epochOf({
      did,
      chainStates: states,
      events,
      limits: { MAX_EPOCH_EVENTS: 2 },
    })
    expect(over.head.saturated).toBe(true)
    expect(over.applied).toHaveLength(3)
    const at = await epochOf({ did, chainStates: states, events, limits: { MAX_EPOCH_EVENTS: 3 } })
    expect(at.head.saturated).toBe(false)
    // Invalid events never count towards saturation.
    const junk = [
      ...events,
      { event: revA.event, sigs: [] },
      await revoke({ signer: root, target: 'x', parents: [digestOf('absent')] }),
    ]
    expect(
      (await epochOf({ did, chainStates: states, events: junk, limits: { MAX_EPOCH_EVENTS: 3 } }))
        .head.saturated,
    ).toBe(false)
  })

  test('the default saturation threshold is MAX_EPOCH_EVENTS', async () => {
    expect(DEFAULT_EPOCH_LIMITS.MAX_EPOCH_EVENTS).toBe(MAX_EPOCH_EVENTS)
    const states = (await chainFolded(chain)).states
    const result = await epochOf({ did, chainStates: states, events: [revA, revB] })
    expect(result.head.saturated).toBe(false)
  })

  test('more than MAX_LOG_EVENTS entries fail the request with LOG_TOO_LARGE', async () => {
    const events = Array.from({ length: MAX_LOG_EVENTS + 1 }, () => null)
    expect(await fold(events)).toEqual({ ok: false, reason: LOG_TOO_LARGE, index: -1 })
    expect((await fold(events.slice(1))).ok).toBe(true)
  })

  test('a member revoke folds with no clock', async () => {
    const log = [revA, revB, renew, child]
    const foldedEarlier = summary(await fold(log))
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2100-01-01'))
    expect(summary(await fold(log))).toEqual(foldedEarlier)
  })
})

describe('totality under hostile presentation', async () => {
  /** A small deterministic generator, so a failing seed reproduces. */
  function rng(seedValue: number): () => number {
    let state = seedValue >>> 0
    return () => {
      state = (state + 0x6d2b79f5) >>> 0
      let t = state
      t = Math.imul(t ^ (t >>> 15), t | 1)
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
      return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32
    }
  }

  const atInception = (await chainFolded([inception])).head
  const stale = await revoke({
    signer: root,
    target: 'did:key:zOld',
    parents: [atInception.epoch],
    on: atInception,
  })
  // Two members root admits in the epoch, one of them twice (a retried add: one key, two
  // incarnations), so the generated events can reach adds that are concurrent, aliased, and
  // removed or denied along some branches and not others.
  const c = memberKeyPair(21)
  const e = memberKeyPair(22)
  const addMember = async (
    pair: { did: string; key: string },
    parents: Array<string>,
    lease = 1_900_000_000,
  ) => {
    return await createAdd({
      seed,
      profile,
      did,
      head,
      parents,
      member: { did: pair.did, key: pair.key, lease },
    })
  }
  const addC = await addMember(c, [epoch])
  const addCRetry = await addMember(c, [epoch], 1_900_000_001)
  const addE = await addMember(e, [digest(revA)])
  // The settled members twice over: they are members in every causal past until removed or denied,
  // so most of their events reach the lifecycle rules instead of stopping at the signer check.
  const signers: Array<EpochSigner> = [
    root,
    signerA,
    signerB,
    signerA,
    signerB,
    { member: { privateKey: c.privateKey, add: digest(addC) } },
    { member: { privateKey: c.privateKey, add: digest(addCRetry) } },
    { member: { privateKey: e.privateKey, add: digest(addE) } },
  ]
  const incarnations = [
    memberA.add,
    memberB.add,
    digest(addC),
    digest(addCRetry),
    digest(addE),
    digestOf('no such add'),
  ]
  const targets = [
    memberA.did,
    memberB.did,
    `#${c.key}`,
    e.did,
    `#${head.keys[0]}`,
    'did:key:zEdge',
  ]
  const pool: Array<SignedEvent<EpochEvent>> = [
    revA,
    revB,
    renew,
    child,
    stale,
    addC,
    addCRetry,
    addE,
  ]
  // Parents drawn from every class the fold distinguishes: the epoch and events of the pool itself,
  // and -- rarely, since each one poisons every descendant -- a chain event, an older epoch's event
  // and an absent digest. Each generated event that applies joins the choices as soon as it exists,
  // so later ones build chains and diamonds of any depth.
  const parentChoices = [epoch, ...pool.filter((event) => event !== stale).map(digest)]
  const foreignParents = [digestOf(inception.event), digest(stale), digestOf('absent')]
  // One event per lifecycle rule, by hand, so every rule is in the pool whatever the generator
  // below happens to draw: they and their refusals are then shuffled and subset like the rest.
  const removesB = await createRemove({
    signer: signerA,
    did,
    head,
    parents: [epoch],
    add: memberB.add,
  })
  const deniesA = await revoke({ signer: root, target: memberA.did, parents: [digest(revB)] })
  pool.push(
    removesB,
    deniesA,
    await revoke({ signer: signerA, target: memberB.did }),
    await revoke({ signer: root, target: `#${head.keys[0]}` }),
    await addMember(a, [epoch]),
    await createRenew({
      signer: signerA,
      did,
      head,
      parents: [epoch],
      add: memberA.add,
      lease: 2_000_000_000,
    }),
    await createRemove({ signer: signerB, did, head, parents: [epoch], add: memberB.add }),
    await createRenew({
      signer: signerB,
      did,
      head,
      parents: [digest(removesB)],
      add: memberA.add,
      lease: 2_000_000_000,
    }),
    await revoke({ signer: signerA, target: 'did:key:zLate', parents: [digest(deniesA)] }),
  )
  // Two of them as parents too, so generated events also land in a past where B is removed or A
  // is denied. The refused ones are not: see the feedback below.
  parentChoices.push(digest(removesB), digest(deniesA))
  for (let n = 0; n < 48; n++) {
    const pick = rng(n + 1000)
    const choose = <TValue>(items: Array<TValue>): TValue => {
      return items[Math.floor(pick() * items.length)] as TValue
    }
    const second = pick() < 0.1 ? choose(foreignParents) : choose(parentChoices)
    const parents = [...new Set([choose(parentChoices), second])]
    const signer = choose(signers)
    let event: SignedEvent<EpochEvent>
    switch (n % 5) {
      case 0:
        event = await createRenew({
          signer,
          did,
          head,
          parents,
          add: choose(incarnations),
          lease: 1_900_000_000 + n,
        })
        break
      case 1:
        event = await createRemove({ signer, did, head, parents, add: choose(incarnations) })
        break
      case 2: {
        // Root's add of a fresh key, or of one already admitted; or the same body claimed by a
        // member, which the fold must refuse whatever its parents.
        const pair = pick() < 0.5 ? memberKeyPair(40 + n) : choose([a, b, c, e])
        const rootAdd = await addMember(pair, parents)
        if ('member' in signer) {
          const claimed = { ...rootAdd.event, by: signer.member.add }
          event = { event: claimed, sigs: await signEvent(claimed, [signer.member.privateKey]) }
        } else {
          event = rootAdd
        }
        break
      }
      default:
        event = await revoke({
          signer,
          target: pick() < 0.5 ? choose(targets) : `did:key:zGen${n}`,
          parents,
        })
    }
    pool.push(event)
    // Only an event that applies becomes a parent: a refused one would leave every descendant
    // pending, and the pool would never get deeper than its first refusal. Refused events stay in
    // the pool all the same, and the foreign parents keep the pending path covered.
    if (
      (
        await detailOf({
          did,
          chainStates: (await chainFolded(chain)).states,
          events: pool,
        })
      ).applied.includes(digest(event))
    ) {
      parentChoices.push(digest(event))
    }
  }

  function shuffled<TValue>(items: Array<TValue>, next: () => number): Array<TValue> {
    const out = [...items]
    for (let i = out.length - 1; i > 0; i--) {
      const j = Math.floor(next() * (i + 1))
      ;[out[i], out[j]] = [out[j] as TValue, out[i] as TValue]
    }
    return out
  }

  test('the pool reaches every lifecycle rule, and events deeper than the epoch', async () => {
    // A generator that only ever produced root revokes off the epoch would pass the property below
    // without exercising a single member rule; this pins what the pool actually covers.
    const states = (await chainFolded(chain)).states
    const detail = await detailOf({ did, chainStates: states, events: pool })
    const reasons = new Set(detail.reasons.values())
    for (const rule of [
      ADD_NOT_ROOT,
      ADD_KEY_ALREADY_MEMBER,
      SELF_RENEW,
      SELF_REMOVE,
      UNKNOWN_MEMBER,
      MEMBER_REVOKES_MEMBER,
      REVOKE_NAMES_ROOT_KEY,
      'signer was removed in the causal state',
      'signer is denied in the causal state',
    ]) {
      expect(reasons, rule).toContain(rule)
    }
    const deep = pool.filter((event) => {
      return (
        detail.applied.includes(digest(event)) &&
        event.event.p.some((parent) => detail.applied.includes(parent))
      )
    })
    expect(deep.length).toBeGreaterThan(5)
  })

  // 150 seeds folded twice each, with a noble Ed25519 verification per signature: about 4.5s
  // locally, and 38s on a loaded CI runner.
  test('no seed throws, and every shuffle of a seed folds to the same head', async () => {
    for (let seedValue = 0; seedValue < 150; seedValue++) {
      const next = rng(seedValue)
      const entries: Array<unknown> = []
      for (const event of pool) {
        if (next() < 0.5) {
          entries.push(event)
          if (next() < 0.3) entries.push(event)
          if (next() < 0.3)
            entries.push({ event: event.event, sigs: await signEvent(event.event, [b.privateKey]) })
          if (next() < 0.2) entries.push({ event: event.event, sigs: [] })
        }
      }
      entries.push(...[null, 7, 'x', {}, [], undefined].filter(() => next() < 0.3))
      let expected: FoldSummary | undefined
      for (let round = 0; round < 2; round++) {
        const order = shuffled(entries, next)
        let result: FoldResult | undefined
        await expect(
          (async () => {
            result = await fold(order)
          })(),
          `seed ${seedValue}`,
        ).resolves.toBeUndefined()
        const seen = summary(result as FoldResult)
        expected ??= seen
        expect(seen, `seed ${seedValue}`).toEqual(expected)
      }
    }
  }, 120_000)
})
