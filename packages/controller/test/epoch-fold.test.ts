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
function detailOf(params: FoldEpochParams): FoldEpochDetail {
  const detail = foldEpochDetailed(params)
  if (!detail.ok) throw new Error(`epoch fold refused: ${detail.reason}`)
  return detail
}

/** {@link foldEpoch}, which these fixtures never drive into the failed-signature refusal. */
function epochOf(params: FoldEpochParams): FoldEpochResult {
  const result = foldEpoch(params)
  if (!result.ok) throw new Error(`epoch fold refused: ${result.reason}`)
  return result
}

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
  snapshot: { members: [memberA, memberB], deny: [] },
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

  test('a refused child never takes down the parent it also names', () => {
    const atInception = chainFolded([inception]).head
    const stale = revoke(root, 'did:key:zOld', [atInception.epoch], atInception)
    const parent = revoke(root, 'did:key:zP')
    // Cross-epoch parents of two kinds: a chain event, and an event of an older epoch.
    for (const foreign of [digestOf(inception.event), digest(stale)]) {
      const crossing = revoke(root, 'did:key:zC', [digest(parent), foreign])
      for (const order of permutations([parent, crossing, stale])) {
        expect(summary(fold(order))).toMatchObject({
          applied: [digest(parent)],
          rejected: 1,
          pending: 0,
          deny: ['did:key:zP'],
        })
      }
    }
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

  test('add is root-only; another member may renew and remove', () => {
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
    expect(summary(fold([memberAdd]))).toMatchObject({ applied: [], rejected: 1 })
    for (const event of [memberRenew, memberRemove]) {
      expect(summary(fold([event]))).toMatchObject({ applied: [digest(event)], rejected: 0 })
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
    const over = epochOf({ did, chainStates: states, events, limits: { MAX_EPOCH_EVENTS: 2 } })
    expect(over.head.saturated).toBe(true)
    expect(over.applied).toHaveLength(3)
    const at = epochOf({ did, chainStates: states, events, limits: { MAX_EPOCH_EVENTS: 3 } })
    expect(at.head.saturated).toBe(false)
    // Invalid events never count towards saturation.
    const junk = [
      ...events,
      { event: revA.event, sigs: [] },
      revoke(root, 'x', [digestOf('absent')]),
    ]
    expect(
      epochOf({ did, chainStates: states, events: junk, limits: { MAX_EPOCH_EVENTS: 3 } }).head
        .saturated,
    ).toBe(false)
  })

  test('the default saturation threshold is MAX_EPOCH_EVENTS', () => {
    expect(DEFAULT_EPOCH_LIMITS.MAX_EPOCH_EVENTS).toBe(MAX_EPOCH_EVENTS)
    const states = chainFolded(chain).states
    const result = epochOf({ did, chainStates: states, events: [revA, revB] })
    expect(result.head.saturated).toBe(false)
  })

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

describe('totality under hostile presentation', () => {
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

  const atInception = chainFolded([inception]).head
  const stale = revoke(root, 'did:key:zOld', [atInception.epoch], atInception)
  // Two members root admits in the epoch, one of them twice (a retried add: one key, two
  // incarnations), so the generated events can reach adds that are concurrent, aliased, and
  // removed or denied along some branches and not others.
  const c = memberKeyPair(21)
  const e = memberKeyPair(22)
  const addMember = (
    pair: { did: string; key: string },
    parents: Array<string>,
    lease = 1_900_000_000,
  ) =>
    createAdd({
      seed,
      profile,
      did,
      head,
      parents,
      member: { did: pair.did, key: pair.key, lease },
    })
  const addC = addMember(c, [epoch])
  const addCRetry = addMember(c, [epoch], 1_900_000_001)
  const addE = addMember(e, [digest(revA)])
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
  const removesB = createRemove({ signer: signerA, did, head, parents: [epoch], add: memberB.add })
  const deniesA = revoke(root, memberA.did, [digest(revB)])
  pool.push(
    removesB,
    deniesA,
    revoke(signerA, memberB.did),
    revoke(root, `#${head.keys[0]}`),
    addMember(a, [epoch]),
    createRenew({
      signer: signerA,
      did,
      head,
      parents: [epoch],
      add: memberA.add,
      lease: 2_000_000_000,
    }),
    createRemove({ signer: signerB, did, head, parents: [epoch], add: memberB.add }),
    createRenew({
      signer: signerB,
      did,
      head,
      parents: [digest(removesB)],
      add: memberA.add,
      lease: 2_000_000_000,
    }),
    revoke(signerA, 'did:key:zLate', [digest(deniesA)]),
  )
  // Two of them as parents too, so generated events also land in a past where B is removed or A
  // is denied. The refused ones are not: see the feedback below.
  parentChoices.push(digest(removesB), digest(deniesA))
  for (let n = 0; n < 48; n++) {
    const pick = rng(n + 1000)
    const choose = <T>(items: Array<T>): T => items[Math.floor(pick() * items.length)] as T
    const second = pick() < 0.1 ? choose(foreignParents) : choose(parentChoices)
    const parents = [...new Set([choose(parentChoices), second])]
    const signer = choose(signers)
    let event: SignedEvent<EpochEvent>
    switch (n % 5) {
      case 0:
        event = createRenew({
          signer,
          did,
          head,
          parents,
          add: choose(incarnations),
          lease: 1_900_000_000 + n,
        })
        break
      case 1:
        event = createRemove({ signer, did, head, parents, add: choose(incarnations) })
        break
      case 2: {
        // Root's add of a fresh key, or of one already admitted; or the same body claimed by a
        // member, which the fold must refuse whatever its parents.
        const pair = pick() < 0.5 ? memberKeyPair(40 + n) : choose([a, b, c, e])
        const rootAdd = addMember(pair, parents)
        if ('member' in signer) {
          const claimed = { ...rootAdd.event, by: signer.member.add }
          event = { event: claimed, sigs: signEvent(claimed, [signer.member.privateKey]) }
        } else {
          event = rootAdd
        }
        break
      }
      default:
        event = revoke(signer, pick() < 0.5 ? choose(targets) : `did:key:zGen${n}`, parents)
    }
    pool.push(event)
    // Only an event that applies becomes a parent: a refused one would leave every descendant
    // pending, and the pool would never get deeper than its first refusal. Refused events stay in
    // the pool all the same, and the foreign parents keep the pending path covered.
    if (
      detailOf({
        did,
        chainStates: chainFolded(chain).states,
        events: pool,
      }).applied.includes(digest(event))
    ) {
      parentChoices.push(digest(event))
    }
  }

  function shuffled<T>(items: Array<T>, next: () => number): Array<T> {
    const out = [...items]
    for (let i = out.length - 1; i > 0; i--) {
      const j = Math.floor(next() * (i + 1))
      ;[out[i], out[j]] = [out[j] as T, out[i] as T]
    }
    return out
  }

  test('the pool reaches every lifecycle rule, and events deeper than the epoch', () => {
    // A generator that only ever produced root revokes off the epoch would pass the property below
    // without exercising a single member rule; this pins what the pool actually covers.
    const states = chainFolded(chain).states
    const detail = detailOf({ did, chainStates: states, events: pool })
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
    const deep = pool.filter(
      (event) =>
        detail.applied.includes(digest(event)) &&
        event.event.p.some((parent) => detail.applied.includes(parent)),
    )
    expect(deep.length).toBeGreaterThan(5)
  })

  test('no seed throws, and every shuffle of a seed folds to the same head', () => {
    for (let seedValue = 0; seedValue < 150; seedValue++) {
      const next = rng(seedValue)
      const entries: Array<unknown> = []
      for (const event of pool) {
        if (next() < 0.5) {
          entries.push(event)
          if (next() < 0.3) entries.push(event)
          if (next() < 0.3)
            entries.push({ event: event.event, sigs: signEvent(event.event, [b.privateKey]) })
          if (next() < 0.2) entries.push({ event: event.event, sigs: [] })
        }
      }
      entries.push(...[null, 7, 'x', {}, [], undefined].filter(() => next() < 0.3))
      let expected: ReturnType<typeof summary> | undefined
      for (let round = 0; round < 2; round++) {
        const order = shuffled(entries, next)
        let result: FoldResult | undefined
        expect(() => {
          result = fold(order)
        }, `seed ${seedValue}`).not.toThrow()
        const seen = summary(result as FoldResult)
        expected ??= seen
        expect(seen, `seed ${seedValue}`).toEqual(expected)
      }
    }
  }, 30_000)
})
