import { CODECS, type DIDDoc, encodeMultibase, encodePeer4, getPeer4ShortForm } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  isMemberEntry,
  keyTarget,
  type MemberEntry,
  type RotateEvent,
  type SignedEvent,
  type StateSnapshot,
  signEvent,
} from '../src/events.js'
import {
  foldLog,
  type KeyState,
  ROTATE_NEEDS_SNAPSHOT,
  SNAPSHOT_DROPS_RETIRED_KEY,
  SNAPSHOT_MALFORMED,
  SNAPSHOT_MEMBER_DID_MISMATCH,
  SNAPSHOT_MEMBER_KEY_IS_ROOT,
  snapshotOf,
} from '../src/fold.js'
import { encodeKey } from '../src/keys.js'
import { denialTargetsMember, memberCarriesKey, validateSnapshot } from '../src/members.js'

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const seed = new Uint8Array(32).fill(1)
const profile = 0
const icp = createInception(seed, profile)
const did = didFromInception(icp.event)
const empty: StateSnapshot = { members: [], deny: [] }

/** The authority key this seed establishes at `(gen, seq)`, in the spelling `k` carries. */
function rootKeyAt(gen: number, seq: number): string {
  return encodeKey(
    deriveKeyPair(seed, authorityPath(profile, gen, seq), 'EdDSA').publicKey,
    'EdDSA',
  )
}

function edKey(fill: number): string {
  return encodeKey(
    deriveKeyPair(new Uint8Array(32).fill(fill), authorityPath(0, 0, 0), 'EdDSA').publicKey,
    'EdDSA',
  )
}

function didKeyMember(key: string, add = digestOf({ add: key })): MemberEntry {
  return { did: `did:key:${key}`, key, add, lease: 1_900_000_000 }
}

function peerDID(keys: Array<string>): string {
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: keys.map((key, i) => ({
      id: `#key-${i}`,
      type: 'Multikey',
      publicKeyMultibase: key,
    })),
    authentication: keys.map((_, i) => `#key-${i}`),
  } as DIDDoc
  return encodePeer4(doc).longForm
}

const member = didKeyMember(edKey(7))

function rotate(prior: SignedEvent['event'], snapshot: StateSnapshot): SignedEvent<RotateEvent> {
  return createRotate({ seed, profile, did, prior, options: { snapshot } })
}

/**
 * A rotate on the inception whose body `mutate` changes, re-signed with the key it reveals, so the
 * only thing wrong with it is the mutation.
 */
function resignedRotate(mutate: (event: RotateEvent) => RotateEvent): SignedEvent<RotateEvent> {
  const valid = rotate(icp.event, { members: [member], deny: [] })
  const event = mutate({ ...valid.event })
  const key = deriveKeyPair(seed, authorityPath(profile, 0, 1), 'EdDSA')
  return { event, sigs: signEvent(event, [key.privateKey]) }
}

function foldReason(log: Array<SignedEvent>) {
  const result = foldLog(did, log)
  return result.ok ? null : { reason: result.reason, index: result.index }
}

describe('a rotate carries the whole state', () => {
  test('a rotate without a snapshot does not fold', () => {
    const bare = resignedRotate(({ m: _m, d: _d, ...rest }) => rest as RotateEvent)
    expect(foldReason([icp, bare])).toEqual({ reason: ROTATE_NEEDS_SNAPSHOT, index: 1 })
  })

  test('a rotate carrying a deny set but no member list does not fold', () => {
    const half = resignedRotate(({ m: _m, ...rest }) => rest as RotateEvent)
    expect(foldReason([icp, half])).toEqual({ reason: ROTATE_NEEDS_SNAPSHOT, index: 1 })
  })

  test('a rotate carrying a member list but no deny set does not fold', () => {
    const half = resignedRotate(({ d: _d, ...rest }) => rest as RotateEvent)
    expect(foldReason([icp, half])).toEqual({ reason: ROTATE_NEEDS_SNAPSHOT, index: 1 })
  })

  test('the re-signing helper produces a rotate that folds when left unchanged', () => {
    expect(foldLog(did, [icp, resignedRotate((event) => event)]).ok).toBe(true)
  })

  test('the state after a rotate is its snapshot', () => {
    const rot = rotate(icp.event, { members: [member], deny: ['did:key:zA'] })
    const result = foldLog(did, [icp, rot])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const head = at(result.states, 1)
    expect([...head.deny]).toEqual(['did:key:zA'])
    expect(head.members.get(member.add)).toEqual({ ...member, removed: false, effective: true })
    expect(head.members.size).toBe(1)
  })

  test('nothing before a rotate contributes to its state', () => {
    const first = rotate(icp.event, { members: [member], deny: ['did:key:zA'] })
    const second = rotate(first.event, empty)
    const result = foldLog(did, [icp, first, second])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 2).members.size).toBe(0)
    expect(at(result.states, 2).deny.size).toBe(0)
  })

  test('a member a snapshot also denies is carried but not effective', () => {
    const byDID = rotate(icp.event, { members: [member], deny: [member.did] })
    const byKey = rotate(icp.event, { members: [member], deny: [keyTarget(member.key)] })
    for (const rot of [byDID, byKey]) {
      const result = foldLog(did, [icp, rot])
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(at(result.states, 1).members.get(member.add)?.effective).toBe(false)
    }
  })

  test('every chain state opens its own epoch and none is saturated', () => {
    const rot = rotate(icp.event, empty)
    const result = foldLog(did, [icp, rot])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    for (const state of result.states) {
      expect(state.epoch).toBe(state.digest)
      expect(state.saturated).toBe(false)
    }
    expect(at(result.states, 0).members.size).toBe(0)
  })

  test('createRotate writes the snapshot it is given as `m` and `d`', () => {
    const rot = rotate(icp.event, { members: [member], deny: ['did:key:zA'] })
    expect(rot.event.m).toEqual([member])
    expect(rot.event.d).toEqual(['did:key:zA'])
  })
})

describe('snapshot members and root keys are disjoint', () => {
  test('a snapshot member pinning a root key is refused', () => {
    // The rotate's own revealed key, then the inception's: both are on the generation's chain.
    for (const key of [rootKeyAt(0, 1), rootKeyAt(0, 0)]) {
      const rot = rotate(icp.event, { members: [didKeyMember(key)], deny: [] })
      expect(rot.event.k).toEqual([rootKeyAt(0, 1)])
      expect(foldReason([icp, rot])).toEqual({ reason: SNAPSHOT_MEMBER_KEY_IS_ROOT, index: 1 })
    }
  })

  test('a snapshot member pinning a committed next key is refused', () => {
    const next = rootKeyAt(0, 2)
    const rot = rotate(icp.event, { members: [didKeyMember(next)], deny: [] })
    expect(rot.event.n).toEqual([digestOf(next)])
    expect(foldReason([icp, rot])).toEqual({ reason: SNAPSHOT_MEMBER_KEY_IS_ROOT, index: 1 })
  })

  test('a reset snapshot is checked against the new generation keys', () => {
    const newKey = rootKeyAt(1, 0)
    const reset = createReset(seed, profile, 1, { members: [didKeyMember(newKey)], deny: [] })
    expect(reset.event.k).toEqual([newKey])
    expect(foldReason([icp, reset])).toEqual({ reason: SNAPSHOT_MEMBER_KEY_IS_ROOT, index: 1 })

    const newNext = rootKeyAt(1, 1)
    const committed = createReset(seed, profile, 1, { members: [didKeyMember(newNext)], deny: [] })
    expect(foldReason([icp, committed])).toEqual({ reason: SNAPSHOT_MEMBER_KEY_IS_ROOT, index: 1 })
  })

  test('a reset snapshot may carry a member pinning a key of the generation it closes', () => {
    const oldKey = rootKeyAt(0, 0)
    const reset = createReset(seed, profile, 1, { members: [didKeyMember(oldKey)], deny: [] })
    expect(foldLog(did, [icp, reset]).ok).toBe(true)
  })
})

describe('a snapshot member DID carries its pinned key', () => {
  test('a did:peer:4 member carrying exactly its pinned key folds', () => {
    const key = edKey(8)
    const peer = { ...didKeyMember(key), did: peerDID([key]) }
    const result = foldLog(did, [icp, rotate(icp.event, { members: [peer], deny: [] })])
    expect(result.ok).toBe(true)
  })

  test('a did:peer:4 member carrying two signing keys is refused', () => {
    const key = edKey(8)
    const peer = { ...didKeyMember(key), did: peerDID([key, edKey(9)]) }
    const rot = rotate(icp.event, { members: [peer], deny: [] })
    expect(foldReason([icp, rot])).toEqual({ reason: SNAPSHOT_MEMBER_DID_MISMATCH, index: 1 })
  })

  test('a member whose DID names another key, or no key, is refused', () => {
    const key = edKey(8)
    const peer = peerDID([key])
    for (const memberDID of [`did:key:${edKey(9)}`, getPeer4ShortForm(peer), 'did:web:x', did]) {
      const rot = rotate(icp.event, {
        members: [{ ...didKeyMember(key), did: memberDID }],
        deny: [],
      })
      expect(foldReason([icp, rot])).toEqual({ reason: SNAPSHOT_MEMBER_DID_MISMATCH, index: 1 })
    }
  })

  test('memberCarriesKey is false for a malformed identifier rather than throwing', () => {
    expect(memberCarriesKey('did:key:z', edKey(8))).toBe(false)
    expect(memberCarriesKey('did:peer:4zQm:zNotADocument', edKey(8))).toBe(false)
  })

  test('memberCarriesKey refuses a did:peer:4 whose single signing key is not Ed25519', () => {
    const bytes = new Uint8Array(33).fill(2)
    const p256 = encodeMultibase(new Uint8Array([...CODECS.ES256, ...bytes]))
    expect(memberCarriesKey(peerDID([p256]), p256)).toBe(false)
    // The same public-key bytes spelled with the Ed25519 tag: only the algorithm check refuses it.
    const retagged = encodeMultibase(new Uint8Array([...CODECS.EdDSA, ...bytes]))
    expect(memberCarriesKey(peerDID([p256]), retagged)).toBe(false)
  })
})

describe('a snapshot entry is well formed', () => {
  // Each case breaks exactly one rule of an otherwise valid snapshot.
  const second = didKeyMember(edKey(8))
  const cases: Array<[string, StateSnapshot]> = [
    ['a negative lease', { members: [{ ...member, lease: -1 }], deny: [] }],
    ['a fractional lease', { members: [{ ...member, lease: 1.5 }], deny: [] }],
    ['an unsafe lease', { members: [{ ...member, lease: 2 ** 53 }], deny: [] }],
    ['a non-string add', { members: [{ ...member, add: 1 as unknown as string }], deny: [] }],
    [
      'an agreement key as the pin',
      {
        members: [
          {
            ...member,
            key: encodeKey(
              deriveKeyPair(seed, agreementPath(0, 5, 0), 'X25519').publicKey,
              'X25519',
            ),
          },
        ],
        deny: [],
      },
    ],
    ['an undecodable pin', { members: [{ ...member, key: 'zNotAKey' }], deny: [] }],
    ['a duplicate add', { members: [member, { ...second, add: member.add }], deny: [] }],
    [
      'two entries pinning one key',
      { members: [member, { ...member, add: digestOf('another incarnation') }], deny: [] },
    ],
    ['a member list that is not an array', { members: member as never, deny: [] }],
    ['a non-object entry', { members: ['did:key:zA' as never], deny: [] }],
    ['a deny set that is not a key list', { members: [member], deny: [1 as never] }],
  ]

  test('the unbroken snapshot folds', () => {
    expect(foldLog(did, [icp, rotate(icp.event, { members: [member, second], deny: [] })]).ok).toBe(
      true,
    )
  })

  for (const [name, snapshot] of cases) {
    test(`a snapshot with ${name} is refused`, () => {
      expect(foldReason([icp, rotate(icp.event, snapshot)])).toEqual({
        reason: SNAPSHOT_MALFORMED,
        index: 1,
      })
    })
  }

  test('isMemberEntry checks the shape the fold carries', () => {
    expect(isMemberEntry(member)).toBe(true)
    expect(isMemberEntry({ ...member, did: 1 })).toBe(false)
    expect(isMemberEntry({ ...member, key: null })).toBe(false)
    expect(isMemberEntry({ ...member, lease: '1' })).toBe(false)
    expect(isMemberEntry(null)).toBe(false)
    expect(isMemberEntry([member])).toBe(false)
  })
})

describe('retired-key denials outlive a rotate', () => {
  const retired = keyTarget(rootKeyAt(0, 0))

  test('a later rotate may not drop a checkpointed retired key', () => {
    const r1 = rotate(icp.event, { members: [], deny: [retired] })
    const r2 = rotate(r1.event, empty)
    expect(foldReason([icp, r1, r2])).toEqual({ reason: SNAPSHOT_DROPS_RETIRED_KEY, index: 2 })
  })

  test('a later rotate that keeps the retired key folds', () => {
    const r1 = rotate(icp.event, { members: [], deny: [retired] })
    const r2 = rotate(r1.event, { members: [], deny: [retired] })
    expect(foldLog(did, [icp, r1, r2]).ok).toBe(true)
  })

  test('a holder DID denial may be dropped by a later snapshot', () => {
    const r1 = rotate(icp.event, { members: [], deny: ['did:key:zA'] })
    const r2 = rotate(r1.event, empty)
    const result = foldLog(did, [icp, r1, r2])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 2).deny.size).toBe(0)
  })

  test('a denial of a key never on the chain is not a tombstone', () => {
    const r1 = rotate(icp.event, { members: [], deny: [keyTarget(edKey(9))] })
    const r2 = rotate(r1.event, empty)
    expect(foldLog(did, [icp, r1, r2]).ok).toBe(true)
  })

  test('a reset owes nothing to the prior generation`s denials, even one naming its own key', () => {
    // The prior chain denied the key the reset is about to establish. Read as a tombstone of the
    // new generation, a blind reset — whose deny set is empty — would be refused for dropping it, and
    // the one recovery path that needs no log knowledge would depend on the log.
    const r1 = rotate(icp.event, { members: [], deny: [keyTarget(rootKeyAt(1, 0))] })
    const result = foldLog(did, [icp, r1, createReset(seed, profile, 1)])
    expect(result.ok).toBe(true)
  })

  test('a reset clears checkpointed retirements', () => {
    const r1 = rotate(icp.event, { members: [], deny: [retired] })
    const reset = createReset(seed, profile, 1)
    const result = foldLog(did, [icp, r1, reset])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 2).deny.size).toBe(0)
  })
})

describe('a reset', () => {
  test('a blind reset is byte-identical per seed, profile and generation', () => {
    expect(createReset(seed, profile, 1)).toEqual(createReset(seed, profile, 1))
    expect(createReset(seed, profile, 1).event).not.toHaveProperty('m')
    expect(createReset(seed, profile, 1).event.d).toEqual([])
  })

  test('a reset with a snapshot folds to that snapshot and starts a new generation', () => {
    const snapshot = { members: [member], deny: ['did:key:zA'] }
    const reset = createReset(seed, profile, 1, snapshot)
    expect(reset.event.m).toEqual([member])
    expect(reset).not.toEqual(createReset(seed, profile, 1))
    const result = foldLog(did, [icp, rotate(icp.event, empty), reset])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const head = at(result.states, 2)
    expect(head.gen).toBe(1)
    expect(head.members.get(member.add)).toEqual({ ...member, removed: false, effective: true })
    expect([...head.deny]).toEqual(['did:key:zA'])
    expect(head.epoch).toBe(head.digest)
  })

  test('a reset carrying only half a snapshot does not fold', () => {
    const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')
    const full = createReset(seed, profile, 1, { members: [member], deny: ['did:key:zA'] })
    const resigned = (event: RotateEvent): SignedEvent<RotateEvent> => ({
      ...full,
      event,
      sigs: signEvent(event, [recovery.privateKey]),
    })
    expect(foldLog(did, [icp, resigned(full.event)]).ok).toBe(true)
    const { m: _m, ...withoutMembers } = full.event
    const { d: _d, ...withoutDeny } = full.event
    for (const half of [withoutMembers, withoutDeny]) {
      expect(foldReason([icp, resigned(half as RotateEvent)])).toEqual({
        reason: 'invalid reset',
        index: 1,
      })
    }
  })

  test('a blind reset carries no member list, so it is not mistaken for half a snapshot', () => {
    expect(foldLog(did, [icp, createReset(seed, profile, 1)]).ok).toBe(true)
  })

  test('a reset carrying neither half folds as blind, to an empty state', () => {
    const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')
    const blind = createReset(seed, profile, 1)
    const { d: _d, ...bare } = blind.event
    const event = bare as RotateEvent
    const result = foldLog(did, [
      icp,
      { ...blind, event, sigs: signEvent(event, [recovery.privateKey]) },
    ])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 1).deny.size).toBe(0)
    expect(at(result.states, 1).members.size).toBe(0)
  })
})

describe('snapshotOf()', () => {
  test('reads every member and denial back out of a state, minus what is dropped', () => {
    const second = didKeyMember(edKey(8))
    const rot = rotate(icp.event, { members: [member, second], deny: ['did:key:zA', 'did:key:zB'] })
    const result = foldLog(did, [icp, rot])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const state = at(result.states, 1)
    expect(snapshotOf(state)).toEqual({
      members: [member, second],
      deny: ['did:key:zA', 'did:key:zB'],
    })
    expect(snapshotOf(state, { deny: ['did:key:zA'], members: [second.add] })).toEqual({
      members: [member],
      deny: ['did:key:zB'],
    })
  })

  test('leaves out a removed member', () => {
    const state: KeyState = {
      ...(foldLog(did, [icp]) as { ok: true; states: Array<KeyState> }).states[0],
      members: new Map([[member.add, { ...member, removed: true, effective: false }]]),
    } as KeyState
    expect(snapshotOf(state).members).toEqual([])
  })
})

describe('validateSnapshot()', () => {
  test('answers null for a valid snapshot', () => {
    expect(
      validateSnapshot({
        snapshot: { members: [member], deny: [] },
        generationKeys: [rootKeyAt(0, 0)],
        generationCommitments: [],
        tombstones: new Set(),
      }),
    ).toBeNull()
  })

  test('a tombstone missing from the deny set is the retired-key reason', () => {
    expect(
      validateSnapshot({
        snapshot: { members: [], deny: [] },
        generationKeys: [rootKeyAt(0, 0)],
        generationCommitments: [],
        tombstones: new Set([keyTarget(rootKeyAt(0, 0))]),
      }),
    ).toBe(SNAPSHOT_DROPS_RETIRED_KEY)
  })
})

describe('denialTargetsMember()', () => {
  const key = edKey(8)
  const long = peerDID([key])
  const peer: MemberEntry = { ...didKeyMember(key), did: long }

  test('matches the pinned key target and the DID, long or short form', () => {
    expect(denialTargetsMember(keyTarget(key), peer)).toBe(true)
    expect(denialTargetsMember(long, peer)).toBe(true)
    expect(denialTargetsMember(getPeer4ShortForm(long), peer)).toBe(true)
  })

  test('matches nothing broader', () => {
    // A did:key of the same public key is a different DID: anyone can write a DID containing a key.
    expect(denialTargetsMember(`did:key:${key}`, peer)).toBe(false)
    expect(denialTargetsMember(key, peer)).toBe(false)
    expect(denialTargetsMember(keyTarget(edKey(9)), peer)).toBe(false)
    expect(denialTargetsMember('did:peer:4zBroken', peer)).toBe(false)
  })
})
