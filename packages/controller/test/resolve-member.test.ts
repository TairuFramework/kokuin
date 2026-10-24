import {
  type DIDDoc,
  type DIDMethodResolver,
  encodePeer4,
  getPeer4ShortForm,
  isIssuerKeyNotFoundError,
  type MemberQuery,
} from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
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
  createReset,
  createRotate,
  didFromInception,
  keyTarget,
  type SignedEvent,
} from '../src/events.js'
import { foldLog, type KeyState, snapshotOf } from '../src/fold.js'
import { createMemoryLogStore } from '../src/history.js'
import { encodeKey } from '../src/keys.js'
import type { ControllerLog } from '../src/log.js'
import {
  type ControllerResolver,
  createControllerResolver,
  createControllerResolverWithin,
} from '../src/resolver.js'
import { EPOCH_SATURATED, KEY_REVOKED, MEMBER_NOT_EFFECTIVE } from '../src/state-resolver.js'
import { fixedViewResolver } from './fixed-view.js'

const seed = new Uint8Array(32).fill(7)
const profile = 0
const icp = createInception(seed, profile)
const did = didFromInception(icp.event)
const root: EpochSigner = { root: { seed, profile } }
const LEASE = 1_900_000_000

function headOf(log: ControllerLog): KeyState {
  const result = foldLog(did, log)
  if (!result.ok) {
    throw new Error(`fixture does not fold: ${result.reason}`)
  }
  return result.head
}

const chain: Array<SignedEvent> = [icp]
const head = headOf({ chain, events: [] })

type Member = { privateKey: Uint8Array; key: string; did: string }

function memberOf(fill: number): Member {
  const privateKey = new Uint8Array(32).fill(fill)
  const key = encodeKey(ed25519.getPublicKey(privateKey), 'EdDSA')
  return { privateKey, key, did: `did:key:${key}` }
}

/** A long-form `did:peer:4` carrying exactly `key` as its one signing key. */
function peerDID(key: string): string {
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase: key }],
    authentication: ['#key-0'],
  } as DIDDoc
  return encodePeer4(doc).longForm
}

const digest = (signed: SignedEvent<EpochEvent>): string => digestOf(signed.event)

function addOf(member: { did: string; key: string }, lease = LEASE): SignedEvent<EpochEvent> {
  return createAdd({
    seed,
    profile,
    did,
    head,
    parents: [head.epoch],
    member: { did: member.did, key: member.key, lease },
  })
}

function revokeOf(target: string, parents: Array<string>): SignedEvent<EpochEvent> {
  return createRevoke({ signer: root, did, head, parents, target })
}

const m = memberOf(31)
const added = addOf(m)
const add = digest(added)
const withMember: ControllerLog = { chain, events: [added] }

function serving(log: ControllerLog): ControllerResolver {
  return createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) })
}

async function refusal(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise
  } catch (error) {
    return error
  }
  throw new Error('expected a refusal')
}

describe('resolveMember()', () => {
  test('an effective member resolves to its pinned key and lease', async () => {
    const resolver = serving(withMember)
    const resolved = await resolver.resolveMember?.(did, { did: m.did, add, gen: 0 })
    expect(resolved).toEqual({
      key: { alg: 'EdDSA', publicKey: ed25519.getPublicKey(m.privateKey) },
      lease: LEASE,
    })
  })

  test('a removed member, a denied member, a wrong DID or a previous generation does not resolve', async () => {
    const removed = createRemove({ signer: root, did, head, parents: [add], add })
    const deniedByDID = revokeOf(m.did, [add])
    const deniedByKey = revokeOf(keyTarget(m.key), [add])
    const other = memberOf(32)
    const cases: Array<[string, ControllerLog, MemberQuery]> = [
      ['removed', { chain, events: [added, removed] }, { did: m.did, add, gen: 0 }],
      ['denied by DID', { chain, events: [added, deniedByDID] }, { did: m.did, add, gen: 0 }],
      ['denied by key', { chain, events: [added, deniedByKey] }, { did: m.did, add, gen: 0 }],
      ['another DID for the incarnation', withMember, { did: other.did, add, gen: 0 }],
      ['an unknown incarnation', withMember, { did: m.did, add: digestOf('never added'), gen: 0 }],
      ['a generation the head is not at', withMember, { did: m.did, add, gen: 1 }],
    ]
    for (const [label, log, query] of cases) {
      const error = await refusal(serving(log).resolveMember?.(did, query) ?? Promise.resolve())
      expect(isIssuerKeyNotFoundError(error), label).toBe(true)
      expect(String(error), label).toContain(MEMBER_NOT_EFFECTIVE)
    }
    // CONTROL — each case's log and query are one change away from resolving.
    await expect(
      serving(withMember).resolveMember?.(did, { did: m.did, add, gen: 0 }),
    ).resolves.toMatchObject({ lease: LEASE })
  })

  test('a long-form and short-form did:peer:4 member DID resolve alike', async () => {
    const peer = memberOf(33)
    const long = peerDID(peer.key)
    const peerAdd = addOf({ did: long, key: peer.key })
    const resolver = serving({ chain, events: [peerAdd] })
    for (const spelling of [long, getPeer4ShortForm(long)]) {
      await expect(
        resolver.resolveMember?.(did, { did: spelling, add: digest(peerAdd), gen: 0 }),
      ).resolves.toMatchObject({ lease: LEASE })
    }
    // Another key's peer DID is a different member, however it is spelled.
    const stranger = peerDID(memberOf(34).key)
    for (const spelling of [stranger, getPeer4ShortForm(stranger)]) {
      await expect(
        resolver.resolveMember?.(did, { did: spelling, add: digest(peerAdd), gen: 0 }),
      ).rejects.toThrow(MEMBER_NOT_EFFECTIVE)
    }
    // A denial in the short form reaches the long-form member.
    const denied = serving({
      chain,
      events: [peerAdd, revokeOf(getPeer4ShortForm(long), [digest(peerAdd)])],
    })
    await expect(
      denied.resolveMember?.(did, { did: long, add: digest(peerAdd), gen: 0 }),
    ).rejects.toThrow(MEMBER_NOT_EFFECTIVE)
  })

  test('a reset with a snapshot carrying the member does not revive the previous generation', async () => {
    const reset = createReset(seed, profile, 1, {
      members: [{ did: m.did, key: m.key, add, lease: LEASE }],
      deny: [],
    })
    const recovered: ControllerLog = { chain: [icp, reset], events: [] }
    // The snapshot keeps the incarnation's add reference: only the generation tells the two apart.
    expect(headOf(recovered).members.get(add)?.effective).toBe(true)
    const resolver = serving(recovered)
    await expect(resolver.resolveMember?.(did, { did: m.did, add, gen: 0 })).rejects.toThrow(
      MEMBER_NOT_EFFECTIVE,
    )
    expect(await resolver.resolveMember?.(did, { did: m.did, add, gen: 1 })).toMatchObject({
      lease: LEASE,
    })
    // A blind reset carries no one: the member is gone in every generation.
    const blind = serving({ chain: [icp, createReset(seed, profile, 1)], events: [] })
    for (const gen of [0, 1]) {
      await expect(blind.resolveMember?.(did, { did: m.did, add, gen })).rejects.toThrow(
        MEMBER_NOT_EFFECTIVE,
      )
    }
  })
})

describe('epoch-aware resolution', () => {
  test('a denial made in the epoch is in the resolved deny set', async () => {
    const audience = 'did:key:zAudience'
    const resolver = serving({ chain, events: [revokeOf(audience, [head.epoch])] })
    expect((await resolver.resolveDenySet?.(did))?.has(audience)).toBe(true)
  })

  test('with a history store, a later presentation withholding a seen epoch event cannot hide it', async () => {
    const audience = 'did:key:zAudience'
    let served: ControllerLog = { chain, events: [added, revokeOf(audience, [add])] }
    const resolver = createControllerResolver({
      loadLog: async () => served,
      history: createMemoryLogStore(),
    })
    expect((await resolver.resolveDenySet?.(did))?.has(audience)).toBe(true)
    // The same chain with the epoch withheld: the answer is the union with memory, not the
    // presentation alone.
    served = { chain, events: [] }
    expect((await resolver.resolveDenySet?.(did))?.has(audience)).toBe(true)
    await expect(resolver.resolveMember?.(did, { did: m.did, add, gen: 0 })).resolves.toMatchObject(
      { lease: LEASE },
    )
  })

  test('a retired key denied in the epoch no longer resolves historically', async () => {
    const rotated = createRotate({
      seed,
      profile,
      did,
      prior: icp.event,
      snapshot: { members: [], deny: [] },
    })
    const rotatedChain = [icp, rotated]
    const settled = headOf({ chain: rotatedChain, events: [] })
    const retired = icp.event.k[0] ?? ''
    // CONTROL — a rotate alone keeps the retired key good for past-issued material.
    await expect(
      serving({ chain: rotatedChain, events: [] }).resolveHistoric?.(did, { kid: `#${retired}` }),
    ).resolves.toMatchObject({ alg: 'EdDSA' })
    const denial = createRevoke({
      signer: root,
      did,
      head: settled,
      parents: [settled.epoch],
      target: keyTarget(retired),
    })
    await expect(
      serving({ chain: rotatedChain, events: [denial] }).resolveHistoric?.(did, {
        kid: `#${retired}`,
      }),
    ).rejects.toThrow(KEY_REVOKED)
  })
})

describe('saturation', () => {
  const events = [revokeOf('did:key:zA', [head.epoch]), revokeOf('did:key:zB', [head.epoch])]
  const saturated: ControllerLog = { chain, events: [added, ...events] }
  const limits = { MAX_EPOCH_EVENTS: 2 }

  async function expectEveryMemberRefused(resolver: DIDMethodResolver): Promise<void> {
    const expected = `${EPOCH_SATURATED}: ${did}`
    await expect(resolver.resolve(did, {})).rejects.toThrow(expected)
    await expect(resolver.resolveHistoric?.(did, {})).rejects.toThrow(expected)
    await expect(
      resolver.resolveMemberHistoric?.(did, { did: m.did, add, gen: 0 }),
    ).rejects.toThrow(expected)
    await expect(resolver.resolveDenySet?.(did)).rejects.toThrow(expected)
    await expect(resolver.resolveAgreementKey?.(did)).rejects.toThrow(expected)
    await expect(resolver.resolveMember?.(did, { did: m.did, add, gen: 0 })).rejects.toThrow(
      expected,
    )
  }

  test('a saturated epoch refuses every resolver member', async () => {
    const plain = createControllerResolverWithin({ loadLog: async () => saturated }, limits)
    await expectEveryMemberRefused(plain)
    await expectEveryMemberRefused(plain.frozen())
    const remembering = createControllerResolverWithin(
      { loadLog: async () => saturated, history: createMemoryLogStore() },
      limits,
    )
    await expectEveryMemberRefused(remembering)

    const result = foldLog(did, saturated)
    if (!result.ok) throw new Error('fixture does not fold')
    await expectEveryMemberRefused(
      fixedViewResolver(did, result.states, { ...result.head, saturated: true }),
    )
  })

  test('CONTROL: the same log under the default threshold answers', async () => {
    const resolver = createControllerResolverWithin({ loadLog: async () => saturated }, {})
    await expect(resolver.resolve(did, {})).resolves.toMatchObject({ alg: 'EdDSA' })
    await expect(resolver.resolveMember?.(did, { did: m.did, add, gen: 0 })).resolves.toMatchObject(
      { lease: LEASE },
    )
  })
})

describe('frozen()', () => {
  const audience = 'did:key:zAudience'
  const query: MemberQuery = { did: m.did, add, gen: 0 }

  function changingStore() {
    let current: ControllerLog = withMember
    let loads = 0
    return {
      loadLog: async (asked: string) => {
        loads++
        return asked === did ? current : undefined
      },
      appendRevokeOfAudience() {
        current = { chain, events: [...current.events, revokeOf(audience, [add])] }
      },
      removeMember() {
        const removal = createRemove({ signer: root, did, head, parents: [add], add })
        current = { chain, events: [...current.events, removal] }
      },
      loads: () => loads,
    }
  }

  test('a frozen view answers membership and denials from one fold even if the store changes between calls', async () => {
    const store = changingStore()
    const resolver = createControllerResolver({ loadLog: store.loadLog })
    const view = resolver.frozen()
    await view.resolveMember?.(did, query)
    store.appendRevokeOfAudience()
    store.removeMember()
    expect((await view.resolveDenySet?.(did))?.has(audience)).toBe(false)
    await expect(view.resolveMember?.(did, query)).resolves.toMatchObject({ lease: LEASE })
    await view.resolve(did, {})
    await expect(view.resolveMemberHistoric?.(did, query)).resolves.toEqual({
      key: { alg: 'EdDSA', publicKey: ed25519.getPublicKey(m.privateKey) },
      lease: LEASE,
      removed: false,
    })
    await view.resolveHistoric?.(did, {})
    await view.resolveAgreementKey?.(did)
    expect(store.loads()).toBe(1)
    // The live resolver re-reads.
    expect((await resolver.resolveDenySet?.(did))?.has(audience)).toBe(true)
    await expect(resolver.resolveMember?.(did, query)).rejects.toThrow(MEMBER_NOT_EFFECTIVE)
    // A fresh view sees the new state.
    expect((await resolver.frozen().resolveDenySet?.(did))?.has(audience)).toBe(true)
  })

  test('a frozen view over a history store also folds once', async () => {
    const store = changingStore()
    const resolver = createControllerResolver({
      loadLog: store.loadLog,
      history: createMemoryLogStore(),
    })
    const view = resolver.frozen()
    await view.resolveMember?.(did, query)
    store.appendRevokeOfAudience()
    expect((await view.resolveDenySet?.(did))?.has(audience)).toBe(false)
    expect((await resolver.resolveDenySet?.(did))?.has(audience)).toBe(true)
    expect(store.loads()).toBe(2)
  })

  test('concurrent first calls share one load', async () => {
    const store = changingStore()
    let release = () => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    // The load reads the store, then stalls: the second call arrives while the first is in flight.
    const view = createControllerResolver({
      loadLog: async (asked) => {
        const read = await store.loadLog(asked)
        await gate
        return read
      },
    }).frozen()
    const first = view.resolveMember?.(did, query)
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(store.loads()).toBe(1)
    store.appendRevokeOfAudience()
    const second = view.resolveDenySet?.(did)
    release()
    const [member, denied] = await Promise.all([first, second])
    expect(store.loads()).toBe(1)
    expect(member).toMatchObject({ lease: LEASE })
    expect(denied?.has(audience)).toBe(false)
  })

  test('a failed load is not remembered as an answer', async () => {
    let fail = true
    const view = createControllerResolver({
      loadLog: async () => {
        if (fail) {
          throw new Error('store unavailable')
        }
        return withMember
      },
    }).frozen()
    await expect(view.resolveMember?.(did, query)).rejects.toThrow('store unavailable')
    fail = false
    await expect(view.resolveMember?.(did, query)).resolves.toMatchObject({ lease: LEASE })
  })

  test('a frozen view answers only for the DIDs its loader knows', async () => {
    const view = createControllerResolver({ loadLog: async () => undefined }).frozen()
    await expect(view.resolve(did, {})).rejects.toThrow(/Unknown DID/)
    await expect(serving(withMember).frozen().resolve('did:key:zNotKokuin', {})).rejects.toThrow(
      /Unknown DID/,
    )
  })
})

describe('historic management membership', () => {
  const query = { did: m.did, add, gen: 0 }
  const removed = createRemove({ signer: root, did, head, parents: [add], add })
  const removedLog = { chain, events: [added, removed] }
  const settle = (log: ControllerLog, deny = headOf(log).deny) => {
    const prior = log.chain.at(-1)
    if (prior === undefined) throw new Error('fixture has no chain')
    return createRotate({
      seed,
      profile,
      did,
      prior: prior.event,
      snapshot: { ...snapshotOf(headOf(log)), deny: [...deny] },
    })
  }

  const carried = settle(withMember)
  const carriedLog = { chain: [icp, carried], events: [] }
  const carriedHead = headOf(carriedLog)
  const removedAfterSettle = createRemove({
    signer: root,
    did,
    head: carriedHead,
    parents: [carriedHead.epoch],
    add,
  })
  const tombstone = settle(removedLog)
  const removedAfterSettleLog = { ...carriedLog, events: [removedAfterSettle] }
  const droppedAfterRemoval = createRotate({
    seed,
    profile,
    did,
    prior: carried.event,
    snapshot: snapshotOf(headOf(removedAfterSettleLog), { members: [add] }),
  })
  const prune = (prior: SignedEvent) =>
    createRotate({ seed, profile, did, prior: prior.event, snapshot: { members: [], deny: [] } })
  const historicCases: Array<[string, ControllerLog, boolean]> = [
    ['effective member', withMember, false],
    ['removed in the current epoch', removedLog, true],
    ['added and removed before settlement', { chain: [icp, tombstone], events: [] }, true],
    ['removed after settlement', { chain: [icp, carried], events: [removedAfterSettle] }, true],
    ['pruned live member', { chain: [icp, carried, prune(carried)], events: [] }, true],
    [
      'removed in epoch then settled without tombstone',
      { chain: [icp, carried, droppedAfterRemoval], events: [] },
      true,
    ],
    ['pruned tombstone', { chain: [icp, tombstone, prune(tombstone)], events: [] }, true],
    [
      'removed then denied at settlement',
      { chain: [icp, settle(removedLog, new Set([m.did]))], events: [] },
      true,
    ],
  ]

  describe.each([false, true])('removed flag with frozen=%s', (frozen) => {
    test.each(historicCases)('%s', async (_label, log, removed) => {
      const resolver = serving(log)
      const view = frozen ? resolver.frozen() : resolver
      await expect(view.resolveMemberHistoric?.(did, query)).resolves.toEqual({
        key: { alg: 'EdDSA', publicKey: ed25519.getPublicKey(m.privateKey) },
        lease: LEASE,
        removed,
      })
    })

    test('re-adding the same key keeps the old incarnation removed and the new one live', async () => {
      const tombstoneLog = { chain: [icp, tombstone], events: [] }
      const next = headOf(tombstoneLog)
      const readded = createAdd({
        seed,
        profile,
        did,
        head: next,
        parents: [next.epoch],
        member: { did: m.did, key: m.key, lease: LEASE },
      })
      const newAdd = digest(readded)
      expect(newAdd).not.toBe(add)
      const resolver = serving({ ...tombstoneLog, events: [readded] })
      const view = frozen ? resolver.frozen() : resolver
      for (const [incarnation, removed] of [
        [add, true],
        [newAdd, false],
      ] as const) {
        await expect(
          view.resolveMemberHistoric?.(did, { ...query, add: incarnation }),
        ).resolves.toEqual({
          key: { alg: 'EdDSA', publicKey: ed25519.getPublicKey(m.privateKey) },
          lease: LEASE,
          removed,
        })
      }
    })
  })

  test('removal preserves historic authority before and after settlement, including later denials', async () => {
    for (const log of [
      removedLog,
      { chain: [icp, settle(removedLog)], events: [] },
      { chain: [icp, settle(removedLog, new Set([m.did]))], events: [] },
      { chain: [icp, settle(removedLog, new Set([keyTarget(m.key)]))], events: [] },
    ]) {
      const resolver = serving(log)
      await expect(resolver.resolveMember?.(did, query)).rejects.toThrow(MEMBER_NOT_EFFECTIVE)
      await expect(resolver.resolveMemberHistoric?.(did, query)).resolves.toMatchObject({
        lease: LEASE,
      })
      await expect(resolver.frozen().resolveMemberHistoric?.(did, query)).resolves.toMatchObject({
        lease: LEASE,
      })
    }
  })

  test('a member carried through settlement can be removed in the next epoch', async () => {
    const rot = settle(withMember)
    const next = headOf({ chain: [icp, rot], events: [] })
    const rmv = createRemove({ signer: root, did, head: next, parents: [next.epoch], add })
    await expect(
      serving({ chain: [icp, rot], events: [rmv] }).resolveMemberHistoric?.(did, query),
    ).resolves.toMatchObject({ lease: LEASE })
    // A previous chain snapshot remains evidence even if root later prunes the member.
    const pruned = createRotate({
      seed,
      profile,
      did,
      prior: rot.event,
      snapshot: { members: [], deny: [] },
    })
    await expect(
      serving({ chain: [icp, rot, pruned], events: [] }).resolveMemberHistoric?.(did, query),
    ).resolves.toMatchObject({ lease: LEASE })
  })

  test('historic fallback refuses evidence checkpointed in an earlier generation', async () => {
    const rot = settle(withMember)
    const before = { chain: [icp, rot], events: [] }
    await expect(serving(before).resolveMemberHistoric?.(did, query)).resolves.toMatchObject({
      lease: LEASE,
    })
    const pruned = createRotate({
      seed,
      profile,
      did,
      prior: rot.event,
      snapshot: { members: [], deny: [] },
    })
    // CONTROL: fallback to the same checkpoint works within its generation.
    await expect(
      serving({ chain: [icp, rot, pruned], events: [] }).resolveMemberHistoric?.(did, query),
    ).resolves.toMatchObject({ lease: LEASE })
    for (const snapshot of [undefined, snapshotOf(headOf(before))]) {
      const reset = createReset(seed, profile, 1, snapshot)
      const resolver = serving({ chain: [icp, rot, reset], events: [] })
      await expect(resolver.resolveMemberHistoric?.(did, query)).rejects.toThrow(
        'not a historic management member',
      )
      const currentQuery = { ...query, gen: 1 }
      if (snapshot === undefined) {
        await expect(resolver.resolveMemberHistoric?.(did, currentQuery)).rejects.toThrow(
          'not a historic management member',
        )
      } else {
        await expect(resolver.resolveMemberHistoric?.(did, currentQuery)).resolves.toMatchObject({
          lease: LEASE,
        })
        await expect(resolver.resolveMember?.(did, currentQuery)).resolves.toMatchObject({
          lease: LEASE,
        })
      }
    }
  })

  test('current DID and key denials refuse pruned live evidence but preserve pruned tombstones', async () => {
    for (const target of [m.did, keyTarget(m.key)]) {
      for (const removed of [false, true]) {
        const rot = settle(removed ? removedLog : withMember)
        const pruned = createRotate({
          seed,
          profile,
          did,
          prior: rot.event,
          snapshot: { members: [], deny: [target] },
        })
        const log = { chain: [icp, rot, pruned], events: [] }
        expect(headOf(log).members.has(add)).toBe(false)
        const result = serving(log).resolveMemberHistoric?.(did, query)
        if (removed) {
          await expect(result).resolves.toMatchObject({ lease: LEASE })
        } else {
          await expect(result).rejects.toThrow('not a historic management member')
        }
      }
    }
  })

  test('unknown, mismatched, reset and denied live incarnations fail closed', async () => {
    const cases: Array<[ControllerLog, MemberQuery]> = [
      [withMember, { ...query, add: digestOf('unknown') }],
      [withMember, { ...query, did: memberOf(32).did }],
      [withMember, { ...query, gen: 1 }],
      [
        { chain: [icp, createReset(seed, profile, 1, snapshotOf(headOf(withMember)))], events: [] },
        query,
      ],
      [{ chain, events: [added, revokeOf(m.did, [add])] }, query],
      [{ chain, events: [added, revokeOf(keyTarget(m.key), [head.epoch])] }, query],
    ]
    for (const [log, asked] of cases) {
      const error = await refusal(
        serving(log).resolveMemberHistoric?.(did, asked) ?? Promise.resolve(),
      )
      expect(isIssuerKeyNotFoundError(error)).toBe(true)
      expect(String(error)).toContain('not a historic management member')
    }
    // CONTROL: the admitted incarnation without denial resolves.
    await expect(serving(withMember).resolveMemberHistoric?.(did, query)).resolves.toMatchObject({
      lease: LEASE,
    })
    const deny = revokeOf(m.did, [head.epoch])
    const refusedAdd = createAdd({
      seed,
      profile,
      did,
      head,
      parents: [digest(deny)],
      member: { did: m.did, key: m.key, lease: LEASE },
    })
    expect(headOf({ chain, events: [deny, refusedAdd] }).members.has(digest(refusedAdd))).toBe(
      false,
    )
    await expect(
      serving({ chain, events: [deny, refusedAdd] }).resolveMemberHistoric?.(did, {
        ...query,
        add: digest(refusedAdd),
      }),
    ).rejects.toThrow('not a historic management member')
  })

  test('a concurrent add and denial admits only historic authority after removal', async () => {
    const denial = revokeOf(m.did, [head.epoch])
    const removal = createRemove({ signer: root, did, head, parents: [add, digest(denial)], add })
    const log = { chain, events: [added, denial, removal] }
    expect(headOf(log).members.get(add)).toMatchObject({ removed: true, effective: false })
    await expect(serving(log).resolveMemberHistoric?.(did, query)).resolves.toMatchObject({
      lease: LEASE,
    })
    const rot = settle(log)
    await expect(
      serving({ chain: [icp, rot], events: [] }).resolveMemberHistoric?.(did, query),
    ).resolves.toMatchObject({ lease: LEASE })
    // CONTROL: without removal the concurrent denial refuses historic authority.
    await expect(
      serving({ chain, events: [added, denial] }).resolveMemberHistoric?.(did, query),
    ).rejects.toThrow('not a historic management member')
  })

  test('historic queries normalise member DIDs', async () => {
    const long = peerDID(m.key)
    const admission = addOf({ did: long, key: m.key })
    await expect(
      serving({ chain, events: [admission] }).resolveMemberHistoric?.(did, {
        did: getPeer4ShortForm(long),
        add: digest(admission),
        gen: 0,
      }),
    ).resolves.toMatchObject({ lease: LEASE })
  })

  test('tombstones survive renewal and cannot sign removal, renewal or revocation', () => {
    const rot = settle(removedLog)
    const nextChain = [icp, rot]
    const next = headOf({ chain: nextChain, events: [] })
    const signer: EpochSigner = { member: { add, privateKey: m.privateKey } }
    const events = [
      createRemove({ signer, did, head: next, parents: [next.epoch], add }),
      createRenew({ signer, did, head: next, parents: [next.epoch], add, lease: LEASE + 1 }),
      createRevoke({ signer, did, head: next, parents: [next.epoch], target: memberOf(32).did }),
    ]
    for (const event of events) {
      const result = foldLog(did, { chain: nextChain, events: [event] })
      expect(result.ok && result.head.members.get(add)).toMatchObject({
        removed: true,
        effective: false,
        lease: LEASE,
      })
      expect(result.ok && result.head.deny.size).toBe(0)
    }
    const renewal = createRenew({
      signer: root,
      did,
      head: next,
      parents: [next.epoch],
      add,
      lease: LEASE + 1,
    })
    expect(headOf({ chain: nextChain, events: [renewal] }).members.get(add)).toMatchObject({
      removed: true,
      effective: false,
    })
    expect(snapshotOf(next, { members: [add] }).removed ?? []).toEqual([])
  })
})
