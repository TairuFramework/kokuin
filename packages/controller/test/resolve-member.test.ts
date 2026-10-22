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
import { foldLog, type KeyState } from '../src/fold.js'
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
