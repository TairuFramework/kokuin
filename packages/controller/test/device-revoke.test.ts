import { describe, expect, test } from 'vitest'

import {
  createDeviceRevoke,
  createInception,
  createReset,
  createRotate,
  deviceRevokeIndex,
  didFromInception,
  digestOf,
  foldLog,
  type MemberEntry,
  type SignedEvent,
  type StateSnapshot,
} from '../src/index.js'

const seed = new Uint8Array(32).fill(1)
const profile = 0
const inception = createInception(seed, profile)
const did = didFromInception(inception.event)
const subject = 'did:key:zStolenDevice'
const empty: StateSnapshot = { members: [], deny: [] }

function rotate(prior: SignedEvent, deny: Array<string> = []): SignedEvent {
  return createRotate({ seed, profile, did, prior: prior.event, snapshot: { members: [], deny } })
}

function assertFolds(chain: Array<SignedEvent>) {
  const folded = foldLog(did, { chain, events: [] })
  if (!folded.ok) throw new Error(folded.reason)
  return folded.head
}

describe('deviceRevokeIndex()', () => {
  test('returns the chain index of a rotate newly denying the subject', () => {
    const plain = rotate(inception)
    const revoke = rotate(plain, [subject])
    const chain = [inception, plain, revoke]
    assertFolds(chain)
    expect(deviceRevokeIndex(did, chain, subject)).toBe(2)
  })

  test('returns undefined for a plain rotate and for an inception alone', () => {
    expect(deviceRevokeIndex(did, [inception], subject)).toBeUndefined()
    expect(deviceRevokeIndex(did, [inception, rotate(inception)], subject)).toBeUndefined()
  })

  test('does not count a reset carrying the denial', () => {
    const reset = createReset(seed, profile, 1, { ...empty, deny: [subject] })
    const chain = [inception, reset, rotate(reset, [subject])]
    assertFolds(chain)
    expect(deviceRevokeIndex(did, chain, subject)).toBeUndefined()
  })

  test('attributes a carried denial to the first rotate that introduced it', () => {
    const revoke = rotate(inception, [subject])
    const chain = [inception, revoke, rotate(revoke, [subject])]
    assertFolds(chain)
    expect(deviceRevokeIndex(did, chain, subject)).toBe(1)
  })

  test('finds re-denial after a reset denial is dropped', () => {
    const reset = createReset(seed, profile, 1, { ...empty, deny: [subject] })
    const undeny = rotate(reset)
    const chain = [inception, reset, undeny, rotate(undeny, [subject])]
    assertFolds(chain)
    expect(deviceRevokeIndex(did, chain, subject)).toBe(3)
  })

  test('returns the first revoke even when a later rotate re-denies the subject', () => {
    const revoke = rotate(inception, [subject])
    const undeny = rotate(revoke)
    const chain = [inception, revoke, undeny, rotate(undeny, [subject])]
    assertFolds(chain)
    expect(deviceRevokeIndex(did, chain, subject)).toBe(1)
  })

  test('matches deny entries exactly as the folded state holds them', () => {
    const qualified = `${subject}#device`
    const chain = [inception, rotate(inception, [qualified])]
    expect(assertFolds(chain).deny.has(qualified)).toBe(true)
    expect(deviceRevokeIndex(did, chain, subject)).toBeUndefined()
    expect(deviceRevokeIndex(did, chain, qualified)).toBe(1)
  })

  test('returns undefined if a later invalid event prevents the whole chain folding', () => {
    const revoke = rotate(inception, [subject])
    const invalid = { ...rotate(revoke, [subject]), sigs: [] }
    expect(deviceRevokeIndex(did, [inception, revoke, invalid], subject)).toBeUndefined()
  })

  test('returns undefined for an empty chain or a different controller DID', () => {
    expect(deviceRevokeIndex(did, [], subject)).toBeUndefined()
    const otherDID = didFromInception(createInception(new Uint8Array(32).fill(2), profile).event)
    expect(
      deviceRevokeIndex(otherDID, [inception, rotate(inception, [subject])], subject),
    ).toBeUndefined()
  })

  test('refuses chain revokes even when marked non-critical', () => {
    const revoke = rotate(inception, [subject])
    for (const crit of [true, false]) {
      const legacy = {
        ...revoke,
        event: { ...revoke.event, t: 'rev', crit },
      } as unknown as SignedEvent
      const chain = [inception, legacy, revoke]
      expect(deviceRevokeIndex(did, chain, subject)).toBeUndefined()
      expect(() => createDeviceRevoke({ seed, profile, did, chain, subject })).toThrow()
    }
  })
})

describe('createDeviceRevoke()', () => {
  test('creates a valid revoke while preserving snapshot members and existing denials', () => {
    const memberKey = createInception(new Uint8Array(32).fill(2), profile).event.k[0]
    if (memberKey == null) throw new Error('Missing member key')
    const member: MemberEntry = {
      did: `did:key:${memberKey}`,
      key: memberKey,
      add: digestOf({ member: memberKey }),
      lease: 1_900_000_000,
    }
    const prior = createRotate({
      seed,
      profile,
      did,
      prior: inception.event,
      snapshot: { members: [member], deny: ['did:key:zOtherDevice'] },
    })
    const chain = [inception, prior]
    const before = structuredClone(chain)
    const revoke = createDeviceRevoke({ seed, profile, did, chain, subject })
    const head = assertFolds([...chain, revoke])
    expect(deviceRevokeIndex(did, [...chain, revoke], subject)).toBe(2)
    expect([...head.deny]).toEqual(['did:key:zOtherDevice', subject])
    expect([...head.members.values()]).toEqual([{ ...member, removed: false, effective: true }])
    expect(chain).toEqual(before)
  })

  test('creates a same-generation revoke after a reset', () => {
    const chain = [inception, createReset(seed, profile, 2)]
    const revoke = createDeviceRevoke({ seed, profile, did, chain, subject })
    expect(assertFolds([...chain, revoke]).gen).toBe(2)
    expect(deviceRevokeIndex(did, [...chain, revoke], subject)).toBe(2)
  })

  test('throws if the subject is already denied', () => {
    const chain = [inception, rotate(inception, [subject])]
    expect(() => createDeviceRevoke({ seed, profile, did, chain, subject })).toThrow(
      /already denied/,
    )
  })

  test('throws if the chain does not fold', () => {
    for (const chain of [[], [inception, { ...rotate(inception), sigs: [] }]]) {
      expect(() => createDeviceRevoke({ seed, profile, did, chain, subject })).toThrow(
        /empty log|invalid rotate/,
      )
    }
  })
})
