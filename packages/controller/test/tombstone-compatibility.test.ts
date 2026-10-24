import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { foldEpochDetailed, UNKNOWN_MEMBER } from '../src/epoch.js'
import type { EpochSigner } from '../src/epoch-events.js'
import { createAdd, createRemove, createRenew, createRevoke } from '../src/epoch-events.js'
import { createInception, createRotate, didFromInception } from '../src/events.js'
import { foldLog, type KeyState, snapshotOf } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'
import type { ControllerLog } from '../src/log.js'
import { createControllerResolver } from '../src/resolver.js'
import { MEMBER_NOT_HISTORIC, resolverOver } from '../src/state-resolver.js'

const seed = new Uint8Array(32).fill(7)
const icp = createInception(seed, 0)
const did = didFromInception(icp.event)
const root: EpochSigner = { root: { seed, profile: 0 } }
function member(fill: number, add: string) {
  const privateKey = new Uint8Array(32).fill(fill)
  const key = encodeKey(ed25519.getPublicKey(privateKey), 'EdDSA')
  return { privateKey, entry: { did: `did:key:${key}`, key, add, lease: 100 } }
}
const old = member(31, 'old-add')
const live = member(32, 'live-add')
const settled = createRotate({
  seed,
  profile: 0,
  did,
  prior: icp.event,
  snapshot: { members: [live.entry], removed: [old.entry], deny: [] },
})
const chain = [icp, settled]
function folded(log: ControllerLog) {
  const result = foldLog(did, log)
  if (!result.ok) throw new Error(result.reason)
  return result
}
const anchor = folded({ chain, events: [] })
const base = { did, head: anchor.head, parents: [anchor.head.epoch] }

describe('settled tombstones and epoch compatibility', () => {
  test('a live member can deny a tombstoned DID without losing its historic evidence', async () => {
    const revoke = createRevoke({
      ...base,
      signer: { member: { privateKey: live.privateKey, add: live.entry.add } },
      target: old.entry.did,
    })
    const log = { chain, events: [revoke] }
    const result = folded(log)
    expect(result.applied).toEqual([digestOf(revoke.event)])
    expect(result.rejected).toBe(0)
    expect([...result.head.deny]).toEqual([old.entry.did])
    expect(result.head.members.has(old.entry.add)).toBe(false)
    const checkpoint = createRotate({
      seed,
      profile: 0,
      did,
      prior: settled.event,
      snapshot: snapshotOf(result.head),
    })
    for (const presented of [log, { chain: [...chain, checkpoint], events: [] }]) {
      const resolver = createControllerResolver({ loadLog: async () => presented })
      for (const view of [resolver, resolver.frozen()]) {
        await expect(
          view.resolveMemberHistoric?.(did, { did: old.entry.did, add: old.entry.add, gen: 0 }),
        ).resolves.toEqual({
          key: { alg: 'EdDSA', publicKey: ed25519.getPublicKey(old.privateKey) },
          lease: 100,
          removed: true,
        })
      }
    }
  })

  test.each(['ren', 'rmv'] as const)(
    'root %s of a tombstoned add has no causal member target',
    (type) => {
      const params = { ...base, signer: root, add: old.entry.add }
      const event = type === 'ren' ? createRenew({ ...params, lease: 101 }) : createRemove(params)
      const result = foldEpochDetailed({ did, chainStates: anchor.states, events: [event] })
      if (!result.ok) throw new Error(result.reason)
      expect(result.applied).toEqual([])
      expect(result.rejected).toBe(1)
      expect(result.reasons.get(digestOf(event.event))).toBe(UNKNOWN_MEMBER)
    },
  )

  test.each(['ren', 'rmv', 'rev'] as const)('a tombstoned signer cannot authorise %s', (type) => {
    const params = {
      ...base,
      signer: { member: { privateKey: old.privateKey, add: old.entry.add } },
    }
    const event =
      type === 'ren'
        ? createRenew({ ...params, add: live.entry.add, lease: 101 })
        : type === 'rmv'
          ? createRemove({ ...params, add: live.entry.add })
          : createRevoke({ ...params, target: 'did:key:zEdge' })
    const result = foldEpochDetailed({ did, chainStates: anchor.states, events: [event] })
    if (!result.ok) throw new Error(result.reason)
    expect(result.applied).toEqual([])
    expect(result.rejected).toBe(1)
    expect(result.reasons.get(digestOf(event.event))).toBe(
      'signer is not a member of the causal state',
    )
    expect([...result.head.members]).toEqual([...anchor.head.members])
    expect([...result.head.deny]).toEqual([])
  })
})

describe('caller-built states without tombstones', () => {
  const { tombstones: _tombstones, ...fields } = anchor.head
  const head: KeyState = fields
  const callerBase = { ...base, head }

  test('snapshotOf preserves the old snapshot output', () => {
    expect(snapshotOf(head)).toEqual({ members: [live.entry], deny: [] })
  })

  test('every epoch builder preserves its event and signature output', () => {
    const params = { seed, profile: 0, member: member(33, 'new-add').entry }
    expect(createAdd({ ...callerBase, ...params })).toEqual(createAdd({ ...base, ...params }))
    expect(createRenew({ ...callerBase, signer: root, add: live.entry.add, lease: 101 })).toEqual(
      createRenew({ ...base, signer: root, add: live.entry.add, lease: 101 }),
    )
    expect(createRemove({ ...callerBase, signer: root, add: live.entry.add })).toEqual(
      createRemove({ ...base, signer: root, add: live.entry.add }),
    )
    expect(createRevoke({ ...callerBase, signer: root, target: old.entry.did })).toEqual(
      createRevoke({ ...base, signer: root, target: old.entry.did }),
    )
  })

  test('historic resolution treats missing head and chain maps as empty', async () => {
    const resolver = resolverOver(async () => ({ states: [head], head }))
    await expect(
      resolver.resolveMemberHistoric?.(did, { did: live.entry.did, add: live.entry.add, gen: 0 }),
    ).resolves.toMatchObject({ lease: 100, removed: false })
    await expect(
      resolver.resolveMemberHistoric?.(did, { did: old.entry.did, add: old.entry.add, gen: 0 }),
    ).rejects.toThrow(MEMBER_NOT_HISTORIC)
  })
})
