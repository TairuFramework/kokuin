import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import { createRemove } from '../src/epoch-events.js'
import type { RotateEvent, SignedEvent } from '../src/events.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  type MemberEntry,
  signEvent,
  verifyReset,
} from '../src/events.js'
import { foldLog, RESET_HAS_TOMBSTONES, snapshotOf } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'
import {
  SNAPSHOT_MALFORMED,
  SNAPSHOT_MEMBER_DID_MISMATCH,
  SNAPSHOT_MEMBER_KEY_IS_ROOT,
} from '../src/members.js'

const seed = new Uint8Array(32).fill(7)
const icp = await createInception({ seed, profile: 0 })
const did = didFromInception(icp.event)
const key = encodeKey({
  publicKey: deriveKeyPair({
    seed: new Uint8Array(32).fill(31),
    path: authorityPath({ profile: 0, gen: 0, seq: 0 }),
    alg: 'EdDSA',
  }).publicKey,
  alg: 'EdDSA',
})
const entry: MemberEntry = { did: `did:key:${key}`, key, add: 'old-add', lease: 100 }
async function folded(members: Array<MemberEntry>, removed: unknown) {
  const rot = await createRotate({
    seed,
    profile: 0,
    did,
    prior: icp.event,
    snapshot: { members, deny: [] },
  })
  const event = { ...rot.event, u: removed }
  return await foldLog({
    did,
    input: {
      chain: [
        icp,
        {
          event,
          sigs: await signEvent(event, [
            deriveKeyPair({
              seed,
              path: authorityPath({ profile: 0, gen: 0, seq: 1 }),
              alg: 'EdDSA',
            }).privateKey,
          ]),
        },
      ],
      events: [],
    },
  })
}
describe('snapshot removed incarnations', () => {
  test('settled tombstones preserve live-only member reads across the chain and head', async () => {
    const live = { ...entry, add: 'live-add' }
    const logs = await Promise.all(
      [true, false].map(async (withTombstone) => {
        const admitted = await createRotate({
          seed,
          profile: 0,
          did,
          prior: icp.event,
          snapshot: { members: [entry], deny: [] },
        })
        const settled = await createRotate({
          seed,
          profile: 0,
          did,
          prior: admitted.event,
          snapshot: { members: [live], ...(withTombstone ? { removed: [entry] } : {}), deny: [] },
        })
        const carried = await createRotate({
          seed,
          profile: 0,
          did,
          prior: settled.event,
          snapshot: { members: [live], ...(withTombstone ? { removed: [entry] } : {}), deny: [] },
        })
        return { chain: [icp, admitted, settled, carried], events: [] }
      }),
    )
    const [withRemoved, withoutRemoved] = await Promise.all(
      logs.map(async (log) => await foldLog({ did, input: log })),
    )
    if (!withRemoved?.ok || !withoutRemoved?.ok) throw new Error('fixture must fold')
    for (const [index, state] of withRemoved.states.entries()) {
      const comparison = withoutRemoved.states[index]
      if (comparison === undefined) throw new Error('fixture states must align')
      expect([...state.members]).toEqual([...comparison.members])
      expect(state.members.has(entry.add)).toBe(index === 1)
      expect(state.tombstones?.has(entry.add)).toBe(index >= 2)
    }
    expect([...withRemoved.head.members]).toEqual([...withoutRemoved.head.members])
    expect(withRemoved.head.members.has(entry.add)).toBe(false)
    expect([...(withRemoved.head.tombstones?.values() ?? [])]).toEqual([entry])
    expect(snapshotOf({ state: withRemoved.head })).toEqual({
      members: [live],
      removed: [entry],
      deny: [],
    })
    expect(snapshotOf({ state: withRemoved.head, members: [entry.add] })).toEqual({
      members: [live],
      deny: [],
    })
    const removal = await createRemove({
      signer: { root: { seed, profile: 0 } },
      did,
      head: withRemoved.head,
      parents: [withRemoved.head.epoch],
      add: live.add,
    })
    const settledLog = logs[0]
    if (settledLog === undefined) throw new Error('fixture log is missing')
    const result = await foldLog({ did, input: { ...settledLog, events: [removal] } })
    if (!result.ok) throw new Error(result.reason)
    expect(result.applied).toEqual([digestOf(removal.event)])
    expect(result.head.members.has(entry.add)).toBe(false)
    expect(result.head.members.get(live.add)).toMatchObject({ removed: true, effective: false })
    expect(snapshotOf({ state: result.head }).removed).toEqual([live, entry])
    expect(
      snapshotOf({ state: result.head, members: [live.add, entry.add] }).removed,
    ).toBeUndefined()
  })

  test('live re-add may share a tombstone pin', async () => {
    const result = await folded([{ ...entry, add: 'new-add' }], [entry])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.head.members.has(entry.add)).toBe(false)
    expect(result.head.tombstones?.get(entry.add)).toEqual(entry)
    expect(result.head.members.get('new-add')).toMatchObject({ removed: false, effective: true })
  })
  test('malformed tombstones and duplicate incarnations fail closed', async () => {
    for (const [members, removed] of [
      [[entry], [entry]],
      [[], [entry, entry]],
      [[], {}],
      [[], [{ ...entry, lease: -1 }]],
      [[], [{ ...entry, key: encodeKey({ publicKey: new Uint8Array(32), alg: 'X25519' }) }]],
    ] as Array<[Array<MemberEntry>, unknown]>) {
      expect(await folded(members, removed)).toMatchObject({
        ok: false,
        reason: SNAPSHOT_MALFORMED,
      })
    }
    expect((await folded([], [entry])).ok).toBe(true)
  })
  test('tombstones obey root disjointness and DID pin checks', async () => {
    const rootKey = icp.event.k[0]
    if (rootKey === undefined) throw new Error('fixture has no root key')
    expect(await folded([], [{ ...entry, did: `did:key:${rootKey}`, key: rootKey }])).toMatchObject(
      {
        ok: false,
        reason: SNAPSHOT_MEMBER_KEY_IS_ROOT,
      },
    )
    expect(await folded([], [{ ...entry, did: `did:key:${rootKey}` }])).toMatchObject({
      ok: false,
      reason: SNAPSHOT_MEMBER_DID_MISMATCH,
    })
    expect((await folded([], [entry])).ok).toBe(true)
  })
  test('old snapshot shape has no removed members', async () => {
    const result = await folded([entry], undefined)
    expect(result.ok && [...result.head.members.values()]).toEqual([
      { ...entry, removed: false, effective: true },
    ])
  })
})

describe('tombstones in resets', () => {
  test('createReset drops removed incarnations from snapshotOf after a removal', async () => {
    const admitted = await createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      snapshot: { members: [entry], deny: [] },
    })
    const before = await foldLog({ did, input: { chain: [icp, admitted], events: [] } })
    if (!before.ok) throw new Error(before.reason)
    const removal = await createRemove({
      signer: { root: { seed, profile: 0 } },
      did,
      head: before.head,
      parents: [before.head.epoch],
      add: entry.add,
    })
    const after = await foldLog({ did, input: { chain: [icp, admitted], events: [removal] } })
    if (!after.ok) throw new Error(after.reason)
    const snapshot = snapshotOf({ state: after.head })
    expect(snapshot.removed).toEqual([entry])
    const reset = await createReset({ seed, profile: 0, gen: 1, snapshot })
    expect('u' in reset.event).toBe(false)
    const result = await foldLog({ did, input: { chain: [icp, admitted, reset], events: [] } })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.head.gen).toBe(1)
    expect(snapshotOf({ state: result.head })).toEqual({ members: [], deny: [] })
    expect(snapshot.removed).toEqual([entry])
  })
  test('a recovery-signed reset refuses the tombstone field regardless of its value', async () => {
    const reset = await createReset({
      seed,
      profile: 0,
      gen: 1,
      snapshot: { members: [entry], deny: [] },
    })
    for (const u of [[], [{ ...entry, add: 'removed-add' }], null, {}, false, undefined]) {
      const event = { ...reset.event, u }
      const signed = {
        ...reset,
        event,
        sigs: await signEvent(event, [
          deriveKeyPair({ seed, path: recoveryPath(0), alg: 'EdDSA' }).privateKey,
        ]),
      }
      expect(
        await verifyReset({ signed: signed as SignedEvent<RotateEvent>, inception: icp.event }),
      ).toBe(true)
      expect(
        await foldLog({
          did,
          input: { chain: [icp, signed as SignedEvent<RotateEvent>], events: [] },
        }),
      ).toMatchObject({
        ok: false,
        reason: RESET_HAS_TOMBSTONES,
      })
    }
    // CONTROL: the same recovery-signed reset without the field folds.
    expect(await verifyReset({ signed: reset, inception: icp.event })).toBe(true)
    expect((await foldLog({ did, input: { chain: [icp, reset], events: [] } })).ok).toBe(true)
  })
  test('tombstones without a full snapshot refuse, even with valid root signatures', async () => {
    const reset = await createReset({ seed, profile: 0, gen: 1 })
    const event = { ...reset.event, u: [entry] }
    const signed = {
      ...reset,
      event,
      sigs: await signEvent(event, [
        deriveKeyPair({ seed, path: recoveryPath(0), alg: 'EdDSA' }).privateKey,
      ]),
    }
    expect(await verifyReset({ signed, inception: icp.event })).toBe(false)
    expect(await verifyReset({ signed: reset, inception: icp.event })).toBe(true)
    const rotate = await createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      snapshot: { members: [], deny: [] },
    })
    const half = { ...rotate.event, m: undefined, u: [entry] }
    expect(
      (
        await foldLog({
          did,
          input: {
            chain: [
              icp,
              {
                event: half,
                sigs: await signEvent(half, [
                  deriveKeyPair({
                    seed,
                    path: authorityPath({ profile: 0, gen: 0, seq: 1 }),
                    alg: 'EdDSA',
                  }).privateKey,
                ]),
              },
            ],
            events: [],
          },
        })
      ).ok,
    ).toBe(false)
  })
})
