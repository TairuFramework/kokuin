import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'

import { digestOf, MAX_CANONICAL_DEPTH } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import { foldEpoch } from '../src/epoch.js'
import { createRevoke } from '../src/epoch-events.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  type MemberEntry,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { createControllerIdentity } from '../src/identity.js'
import { encodeKey } from '../src/keys.js'
import { snapshotEntries } from '../src/log-snapshot.js'

const seed = new Uint8Array(32).fill(7)
const profile = 0

function present<TValue>(value: TValue | undefined): TValue {
  if (value === undefined) throw new Error('Missing fixture value')
  return value
}

function memberEntry(label: string): MemberEntry {
  const key = encodeKey({
    publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(11)),
    alg: 'EdDSA',
  })
  return { did: `did:key:${key}`, key, add: digestOf(label), lease: 1_900_000_000 }
}

async function fixture() {
  const inception = await createInception({ seed, profile })
  const did = didFromInception(inception.event)
  const member = memberEntry('live member')
  const removed = memberEntry('removed member')
  const snapshot = { members: [member], removed: [removed], deny: ['did:key:denied'] }
  const rotate = await createRotate({ seed, profile, did, prior: inception.event, snapshot })
  const input = { chain: [inception, rotate], events: [] }
  return { inception, did, member, removed, snapshot, rotate, input }
}

function gatedCrypto() {
  const started = Promise.withResolvers<void>()
  const gate = Promise.withResolvers<void>()
  const crypto: CryptoProvider = {
    ...nobleCrypto,
    async verifyBatch(items) {
      const result = await nobleCrypto.verifyBatch(items)
      started.resolve()
      await gate.promise
      return result
    },
  }
  return { crypto, waiting: started.promise, release: () => gate.resolve() }
}

const epochFixture = await fixture()
const chainFold = await foldLog({ did: epochFixture.did, input: epochFixture.input })
if (!chainFold.ok) throw new Error(chainFold.reason)

describe.each(['available', 'removed'])('structuredClone %s', (runtime) => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'structuredClone')

  beforeEach(() => {
    if (runtime === 'removed') {
      expect(Reflect.deleteProperty(globalThis, 'structuredClone')).toBe(true)
      expect(globalThis.structuredClone).toBeUndefined()
    }
  })

  afterEach(() => {
    if (descriptor === undefined) Reflect.deleteProperty(globalThis, 'structuredClone')
    else Object.defineProperty(globalThis, 'structuredClone', descriptor)
  })

  test('folds a valid inception-only log', async () => {
    const inception = await createInception({ seed, profile })
    const did = didFromInception(inception.event)
    const result = await foldLog({ did, input: { chain: [inception], events: [] } })
    expect(result).toMatchObject({ ok: true, head: { did, gen: 0, seq: 0 } })
  })

  test('builds and folds rotate and reset member snapshots', async () => {
    const { inception, did, rotate, snapshot } = await fixture()
    const reset = await createReset({ seed, profile, gen: 1, snapshot })
    const result = await foldLog({ did, input: { chain: [inception, rotate, reset], events: [] } })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error(result.reason)
    expect(result.states).toHaveLength(3)
    expect(result.head).toMatchObject({ gen: 1, seq: 0 })
    expect([...result.head.members.values()]).toEqual([
      { ...snapshot.members[0], removed: false, effective: true },
    ])
    present(snapshot.members[0]).lease = 0
    present(snapshot.removed[0]).lease = 0
    expect(rotate.event.m?.[0]?.lease).toBe(1_900_000_000)
    expect(rotate.event.u?.[0]?.lease).toBe(1_900_000_000)
    expect(reset.event.m?.[0]?.lease).toBe(1_900_000_000)
  })

  test('constructs a controller identity that signs as the controller DID', async () => {
    const inception = await createInception({ seed, profile })
    const identity = await createControllerIdentity({
      seed,
      profile,
      log: { chain: [inception], events: [] },
    })
    const did = didFromInception(inception.event)
    expect(identity.id).toBe(did)
    expect((await identity.signToken({ payload: { hello: 'world' } })).payload.iss).toBe(did)
  })

  test('folds an epoch from supplied chainStates', async () => {
    const result = await foldEpoch({
      did: epochFixture.did,
      chainStates: chainFold.states,
      events: [],
    })
    expect(result).toMatchObject({ ok: true, head: { gen: 0, seq: 1 }, rejected: 0 })
  })

  test('owns nested log input before asynchronous verification', async () => {
    const { did, inception, rotate, input } = await fixture()
    const folded = await foldLog({ did, input })
    if (!folded.ok) throw new Error(folded.reason)
    const revoke = await createRevoke({
      did,
      head: folded.head,
      parents: [folded.head.epoch],
      signer: { root: { seed, profile } },
      target: 'did:key:original',
    })
    const log = { chain: [inception, rotate], events: [revoke] }
    const key = inception.event.k[0]
    const gate = gatedCrypto()
    const pending = foldLog({ did, input: log, crypto: gate.crypto })
    try {
      await gate.waiting
      inception.event.k[0] = 'forged key'
      inception.sigs.length = 0
      present(rotate.event.m?.[0]).lease = 0
      present(rotate.event.d)[0] = 'did:key:forged'
      revoke.event.x = 'did:key:forged'
    } finally {
      gate.release()
    }
    const result = await pending
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error(result.reason)
    expect(result.states[0]?.keys).toEqual([key])
    expect([...result.head.members.values()][0]?.lease).toBe(1_900_000_000)
    expect([...result.head.deny]).toEqual(['did:key:denied', 'did:key:original'])
    expect(result.applied).toHaveLength(1)
  })

  test('mutating returned state leaves caller log arrays and objects intact', async () => {
    const { did, input, rotate, member } = await fixture()
    const result = await foldLog({ did, input })
    if (!result.ok) throw new Error(result.reason)
    const originalKeys = [...rotate.event.k]
    result.head.keys[0] = 'changed head key'
    present(result.states[1]).agreement.length = 0
    present(result.head.members.get(member.add)).lease = 0
    expect(rotate.event.k).toEqual(originalKeys)
    expect(rotate.event.ka).toHaveLength(1)
    expect(rotate.event.m?.[0]?.lease).toBe(1_900_000_000)
  })

  test('epoch fold owns chainStates Maps, Sets and nested member values during verification', async () => {
    const { did, input, member, removed } = await fixture()
    const folded = await foldLog({ did, input })
    if (!folded.ok) throw new Error(folded.reason)
    const anchor = present(folded.states[1])
    const revoke = await createRevoke({
      did,
      head: anchor,
      parents: [anchor.epoch],
      signer: { root: { seed, profile } },
      target: 'did:key:original',
    })
    const originalKeys = [...anchor.keys]
    const gate = gatedCrypto()
    const pending = foldEpoch({
      did,
      chainStates: folded.states,
      events: [revoke],
      crypto: gate.crypto,
    })
    try {
      await gate.waiting
      anchor.keys[0] = 'caller changed key'
      present(anchor.members.get(member.add)).lease = 1
      present(anchor.tombstones?.get(removed.add)).lease = 1
      ;(anchor.deny as Set<string>).add('did:key:forged')
    } finally {
      gate.release()
    }
    const result = await pending
    if (!result.ok) throw new Error(result.reason)
    expect(result.head.members).toBeInstanceOf(Map)
    expect(result.head.tombstones).toBeInstanceOf(Map)
    expect(result.head.deny).toBeInstanceOf(Set)
    expect(result.head.keys).toEqual(originalKeys)
    expect(result.head.members.get(member.add)?.lease).toBe(1_900_000_000)
    expect(result.head.tombstones?.get(removed.add)?.lease).toBe(1_900_000_000)
    expect([...result.head.deny]).toEqual(['did:key:denied', 'did:key:original'])
    result.head.keys[0] = 'returned changed key'
    present(result.head.members.get(member.add)).lease = 2
    present(result.head.tombstones?.get(removed.add)).lease = 2
    ;(result.head.deny as Set<string>).clear()
    expect(anchor.keys).toEqual(['caller changed key'])
    expect(anchor.members.get(member.add)?.lease).toBe(1)
    expect(anchor.tombstones?.get(removed.add)?.lease).toBe(1)
    expect([...anchor.deny]).toEqual(['did:key:denied', 'did:key:forged'])
  })

  test('snapshots nested arrays, undefined members and own __proto__ without prototype pollution', async () => {
    const inception = await createInception({ seed, profile })
    const extra = JSON.parse('{"__proto__":{"polluted":true},"nested":[{"value":7}]}')
    extra.optional = undefined
    const event = { ...inception.event, extra }
    const privateKey = deriveKeyPair({
      seed,
      path: authorityPath({ profile, gen: 0, seq: 0 }),
      alg: 'EdDSA',
    }).privateKey
    const signed = { event, sigs: await signEvent(event, [privateKey]) }
    const owned = snapshotEntries([signed])[0] as typeof signed
    expect(Object.hasOwn(owned.event.extra, 'optional')).toBe(true)
    expect(owned.event.extra.optional).toBeUndefined()
    expect(Object.hasOwn(owned.event.extra, '__proto__')).toBe(true)
    expect(Object.getPrototypeOf(owned.event.extra)).toBe(Object.prototype)
    expect(Object.getOwnPropertyDescriptor(owned.event.extra, '__proto__')?.value).toEqual({
      polluted: true,
    })
    expect(Object.hasOwn(Object.prototype, 'polluted')).toBe(false)
    extra.nested[0].value = 8
    present(Object.getOwnPropertyDescriptor(extra, '__proto__')).value.polluted = false
    expect(owned.event.extra.nested).toEqual([{ value: 7 }])
    expect(Object.getOwnPropertyDescriptor(owned.event.extra, '__proto__')?.value).toEqual({
      polluted: true,
    })
    expect(
      await foldLog({
        did: didFromInception(owned.event),
        input: { chain: [owned], events: [] },
      }),
    ).toMatchObject({ ok: true })
  })

  test('refuses malformed and non-canonicalizable entries with the existing fold results', async () => {
    const inception = await createInception({ seed, profile })
    const did = didFromInception(inception.event)
    const cycle: Record<string, unknown> = {}
    cycle.self = cycle
    let deep: unknown = 0
    for (let i = 0; i < MAX_CANONICAL_DEPTH; i++) deep = [deep]
    const values = [
      Number.POSITIVE_INFINITY,
      Number.NaN,
      1n,
      Symbol('uncloneable'),
      () => 1,
      new Date(0),
      new Map(),
      new Set(),
      new Uint8Array([1]),
      [undefined],
      cycle,
      deep,
    ]
    const entries: Array<unknown> = [
      null,
      undefined,
      {},
      { event: inception.event, sigs: [1] },
      ...values.map((value) => ({
        event: { ...inception.event, extra: value },
        sigs: inception.sigs,
      })),
    ]
    for (const entry of entries) {
      expect(await foldLog({ did, input: { chain: [entry as SignedEvent], events: [] } })).toEqual({
        ok: false,
        reason: 'malformed event',
        index: 0,
      })
      expect(
        await foldLog({ did, input: { chain: [inception, entry as SignedEvent], events: [] } }),
      ).toEqual({ ok: false, reason: 'malformed event', index: 1 })
    }
    expect(
      await foldLog({ did, input: { chain: [inception], events: entries as never } }),
    ).toMatchObject({ ok: true, rejected: entries.length, pending: 0, applied: [] })
  })
})
