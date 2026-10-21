import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  type AddEvent,
  createAdd,
  createRemove,
  createRenew,
  createRevoke,
  type EpochEvent,
  isEpochEventShape,
  verifyEpochSignature,
} from '../src/epoch-events.js'
import { createInception, createRotate, didFromInception, type SignedEvent } from '../src/events.js'
import { foldLog, type KeyState } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'
import { DEFAULT_LEASE_SECONDS, MAX_EVENT_BYTES, MAX_EVENT_PARENTS } from '../src/limits.js'

const seed = new Uint8Array(32).fill(1)
const profile = 0
const inception = createInception(seed, profile)
const did = didFromInception(inception.event)

function headOf(events: Array<SignedEvent>): KeyState & { epoch: string } {
  const result = foldLog(did, events)
  if (!result.ok) {
    throw new Error(`fixture log does not fold: ${result.reason}`)
  }
  const state = result.states.at(-1)
  if (state === undefined) {
    throw new Error('fixture log folded to no state')
  }
  return { ...state, epoch: state.digest }
}

function memberKeyPair(): { privateKey: Uint8Array; key: string; did: string } {
  const privateKey = ed25519.utils.randomSecretKey()
  const key = encodeKey(ed25519.getPublicKey(privateKey), 'EdDSA')
  return { privateKey, key, did: `did:key:${key}` }
}

const head = headOf([inception])
const m = memberKeyPair()
const other = memberKeyPair()
const member = { did: m.did, key: m.key, lease: 1_800_000_000 }
const memberSigner = { member: { privateKey: m.privateKey, add: 'A' } }

/** A copy of a valid signed add with one member of its event body replaced or removed. */
function withEvent(
  signed: SignedEvent<AddEvent>,
  mutate: (event: Record<string, unknown>) => void,
): unknown {
  const event: Record<string, unknown> = { ...signed.event }
  mutate(event)
  return { ...signed, event }
}

describe('builders', () => {
  test('a root add names the epoch and its parents and verifies under the chain keys', () => {
    const add = createAdd({ seed, profile, did, head, parents: [head.epoch], member })
    expect(add.event).toMatchObject({
      v: 1,
      t: 'add',
      i: did,
      g: head.gen,
      e: head.epoch,
      p: [head.epoch],
      crit: true,
      did: m.did,
      key: m.key,
      lease: member.lease,
    })
    expect(add.event.by).toBeUndefined()
    expect(isEpochEventShape(add)).toBe(true)
    expect(verifyEpochSignature(add, { rootKeys: head.keys })).toBe(true)
  })

  test('a root signer derives the key at the head`s key position, not the inception`s', () => {
    const rot = createRotate({ seed, profile, did, prior: inception.event })
    const rotated = headOf([inception, rot])
    const add = createAdd({ seed, profile, did, head: rotated, parents: [rotated.epoch], member })
    expect(verifyEpochSignature(add, { rootKeys: rotated.keys })).toBe(true)
    expect(verifyEpochSignature(add, { rootKeys: head.keys })).toBe(false)
  })

  test('a root signer whose key the head does not publish is refused at build time', () => {
    const rot = createRotate({ seed, profile, did, prior: inception.event })
    const rotated = headOf([inception, rot])
    // The inception's position with the rotated head's keys: the derived key is the retired one.
    const stale = { ...rotated, keySeq: 0 }
    expect(() =>
      createAdd({ seed, profile, did, head: stale, parents: [stale.epoch], member }),
    ).toThrow(/does not publish/)
  })

  test('a member revoke names its signer and verifies only under the pinned key', () => {
    const rev = createRevoke({
      signer: memberSigner,
      did,
      head,
      parents: [head.epoch],
      target: 'did:key:zX',
    })
    expect(rev.event).toMatchObject({ t: 'rev', x: 'did:key:zX', e: head.epoch, crit: true })
    expect(rev.event.by).toBe('A')
    expect(isEpochEventShape(rev)).toBe(true)
    expect(verifyEpochSignature(rev, { memberKey: m.key })).toBe(true)
    expect(verifyEpochSignature(rev, { memberKey: other.key })).toBe(false)
  })

  test('a root renew, remove and revoke carry no signer reference', () => {
    const root = { root: { seed, profile } }
    const parents = [head.epoch]
    const built = [
      createRenew({ signer: root, did, head, parents, add: 'A', lease: DEFAULT_LEASE_SECONDS }),
      createRemove({ signer: root, did, head, parents, add: 'A' }),
      createRevoke({ signer: root, did, head, parents, target: 'did:key:zX' }),
    ]
    expect(built.map((signed) => signed.event.t)).toEqual(['ren', 'rmv', 'rev'])
    for (const signed of built) {
      expect(signed.event.by).toBeUndefined()
      expect(isEpochEventShape(signed)).toBe(true)
      expect(verifyEpochSignature(signed, { rootKeys: head.keys })).toBe(true)
    }
  })

  test('a member renew and remove name their target incarnation and their signer', () => {
    const parents = [head.epoch]
    const ren = createRenew({ signer: memberSigner, did, head, parents, add: 'B', lease: 5 })
    const rmv = createRemove({ signer: memberSigner, did, head, parents, add: 'B' })
    expect(ren.event).toMatchObject({ t: 'ren', add: 'B', lease: 5, by: 'A' })
    expect(rmv.event).toMatchObject({ t: 'rmv', add: 'B', by: 'A' })
    expect(verifyEpochSignature(ren, { memberKey: m.key })).toBe(true)
    expect(verifyEpochSignature(rmv, { memberKey: m.key })).toBe(true)
  })

  test('parents are written sorted and deduplicated', () => {
    const add = createAdd({
      seed,
      profile,
      did,
      head,
      parents: ['zc', 'za', 'zc', 'zb', 'za'],
      member,
    })
    expect(add.event.p).toEqual(['za', 'zb', 'zc'])
  })

  test('builders refuse parents the shape guard would refuse', () => {
    expect(() => createAdd({ seed, profile, did, head, parents: [], member })).toThrow(
      /at least one parent/,
    )
    const many = Array.from({ length: MAX_EVENT_PARENTS + 1 }, (_, i) => `z${i}`)
    expect(() => createAdd({ seed, profile, did, head, parents: many, member })).toThrow(/parent/)
    // Duplicates collapse before the count, so this many entries naming few parents is fine.
    const repeated = Array.from({ length: MAX_EVENT_PARENTS + 1 }, () => head.epoch)
    expect(createAdd({ seed, profile, did, head, parents: repeated, member }).event.p).toEqual([
      head.epoch,
    ])
  })

  test('builders refuse a non-integer lease rather than emit an unfoldable event', () => {
    expect(() =>
      createAdd({
        seed,
        profile,
        did,
        head,
        parents: [head.epoch],
        member: { ...member, lease: 1.5 },
      }),
    ).toThrow()
    expect(() =>
      createRenew({ signer: memberSigner, did, head, parents: [head.epoch], add: 'B', lease: -1 }),
    ).toThrow()
  })
})

describe('isEpochEventShape()', () => {
  const add = createAdd({ seed, profile, did, head, parents: [head.epoch], member })

  test('accepts a valid add', () => {
    expect(isEpochEventShape(add)).toBe(true)
  })

  test.each<[string, (event: Record<string, unknown>) => void]>([
    ['no parents', (event) => (event.p = [])],
    ['duplicate parents', (event) => (event.p = [head.epoch, head.epoch])],
    [
      'more than MAX_EVENT_PARENTS',
      (event) => (event.p = Array.from({ length: MAX_EVENT_PARENTS + 1 }, (_, i) => `z${i}`)),
    ],
    ['a non-string parent', (event) => (event.p = [head.epoch, 7])],
    ['a non-array parent list', (event) => (event.p = head.epoch)],
    ['an oversized body', (event) => (event.did = `did:key:z${'a'.repeat(MAX_EVENT_BYTES)}`)],
    ['a missing crit', (event) => delete event.crit],
    ['crit false', (event) => (event.crit = false)],
    ['a missing version', (event) => delete event.v],
    ['another version', (event) => (event.v = 2)],
    ['an unknown type', (event) => (event.t = 'icp')],
    ['a non-string identifier', (event) => (event.i = 1)],
    ['a fractional generation', (event) => (event.g = 0.5)],
    ['a negative generation', (event) => (event.g = -1)],
    ['a missing epoch', (event) => delete event.e],
    ['a non-string signer reference', (event) => (event.by = 1)],
    ['a missing member DID', (event) => delete event.did],
    ['a non-string member key', (event) => (event.key = 1)],
    ['a missing lease', (event) => delete event.lease],
    ['a fractional lease', (event) => (event.lease = 1.5)],
    ['a string lease', (event) => (event.lease = '1800000000')],
    ['a non-finite lease', (event) => (event.lease = Number.POSITIVE_INFINITY)],
  ])('refuses %s', (_, mutate) => {
    expect(isEpochEventShape(withEvent(add, mutate))).toBe(false)
  })

  test('refuses a body exactly one byte past the limit and accepts one at it', () => {
    // Pad the member DID so the body lands on the boundary; length counts UTF-8 bytes of ASCII.
    const base = new TextEncoder().encode(JSON.stringify(add.event)).length
    const fill = (extra: number) =>
      withEvent(add, (event) => (event.did = `${add.event.did}${'a'.repeat(extra)}`))
    expect(isEpochEventShape(fill(MAX_EVENT_BYTES - base))).toBe(true)
    expect(isEpochEventShape(fill(MAX_EVENT_BYTES - base + 1))).toBe(false)
  })

  test('refuses per-type fields missing from the other types', () => {
    const root = { root: { seed, profile } }
    const parents = [head.epoch]
    const ren = createRenew({ signer: root, did, head, parents, add: 'A', lease: 5 })
    const rmv = createRemove({ signer: root, did, head, parents, add: 'A' })
    const rev = createRevoke({ signer: root, did, head, parents, target: 'did:key:zX' })
    const strip = (signed: SignedEvent<EpochEvent>, field: string) => {
      const event: Record<string, unknown> = { ...signed.event }
      delete event[field]
      return { ...signed, event }
    }
    expect(isEpochEventShape(strip(ren, 'add'))).toBe(false)
    expect(isEpochEventShape(strip(ren, 'lease'))).toBe(false)
    expect(isEpochEventShape(strip(rmv, 'add'))).toBe(false)
    expect(isEpochEventShape(strip(rev, 'x'))).toBe(false)
  })

  test('refuses a malformed envelope', () => {
    expect(isEpochEventShape(null)).toBe(false)
    expect(isEpochEventShape({ event: add.event })).toBe(false)
    expect(isEpochEventShape({ ...add, sigs: [] })).toBe(false)
    expect(isEpochEventShape({ ...add, sigs: [1] })).toBe(false)
    expect(isEpochEventShape({ ...add, recoveryKey: m.key })).toBe(false)
    expect(isEpochEventShape({ ...add, event: [] })).toBe(false)
  })

  test('refuses a body the canonicalizer cannot encode', () => {
    expect(isEpochEventShape(withEvent(add, (event) => (event.extra = Number.NaN)))).toBe(false)
  })
})

describe('verifyEpochSignature()', () => {
  const add = createAdd({ seed, profile, did, head, parents: [head.epoch], member })
  const rev = createRevoke({
    signer: memberSigner,
    did,
    head,
    parents: [head.epoch],
    target: 'did:key:zX',
  })

  test('a root event does not verify under a member key, nor a member event under the root', () => {
    expect(verifyEpochSignature(add, { memberKey: head.keys[0] ?? '' })).toBe(false)
    expect(verifyEpochSignature(rev, { rootKeys: [m.key] })).toBe(false)
  })

  test('a member event must carry exactly one signature', () => {
    const [sig] = rev.sigs
    expect(sig).toBeDefined()
    expect(verifyEpochSignature({ ...rev, sigs: [] }, { memberKey: m.key })).toBe(false)
    expect(
      verifyEpochSignature({ ...rev, sigs: [sig ?? '', sig ?? ''] }, { memberKey: m.key }),
    ).toBe(false)
  })

  test('a root event is n-of-n over the root keys', () => {
    expect(verifyEpochSignature(add, { rootKeys: [...head.keys, m.key] })).toBe(false)
    expect(verifyEpochSignature(add, { rootKeys: [] })).toBe(false)
  })

  test('a signature does not survive any change to the body', () => {
    const moved = { ...add, event: { ...add.event, lease: add.event.lease + 1 } }
    expect(verifyEpochSignature(moved, { rootKeys: head.keys })).toBe(false)
    const reparented = { ...rev, event: { ...rev.event, p: [digestOf('elsewhere')] } }
    expect(verifyEpochSignature(reparented, { memberKey: m.key })).toBe(false)
  })

  test('is total on a body the canonicalizer cannot encode', () => {
    const broken = { ...add, event: { ...add.event, lease: Number.NaN } }
    expect(verifyEpochSignature(broken, { rootKeys: head.keys })).toBe(false)
    expect(verifyEpochSignature(broken, { memberKey: m.key })).toBe(false)
  })
})
