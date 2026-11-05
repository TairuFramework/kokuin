import { encodePeer4 } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  createDeviceRevoke,
  createInception,
  createReset,
  createRotate,
  deviceRevokeIndex,
  deviceRevokeIndices,
  didFromInception,
  digestOf,
  foldLog,
  type MemberEntry,
  type SignedEvent,
  type StateSnapshot,
} from '../src/index.js'

const seed = new Uint8Array(32).fill(1)
const profile = 0
const inception = await createInception({ seed, profile })
const did = didFromInception(inception.event)
const subject = 'did:key:zStolenDevice'
const empty: StateSnapshot = { members: [], deny: [] }
const deviceKey = (await createInception({ seed: new Uint8Array(32).fill(2), profile })).event.k[0]
if (deviceKey == null) throw new Error('Missing device key')
const { longForm, shortForm } = encodePeer4({
  '@context': ['https://www.w3.org/ns/did/v1'],
  verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase: deviceKey }],
  authentication: ['#key-0'],
})
const peerForms = [
  { denied: longForm, equivalent: shortForm },
  { denied: shortForm, equivalent: longForm },
]

async function skippedInception(prior: SignedEvent): Promise<SignedEvent> {
  const next = await rotate(prior)
  return {
    ...next,
    event: { ...next.event, t: 'icp', crit: false },
    sigs: [],
  } as unknown as SignedEvent
}

async function rotate(prior: SignedEvent, deny: Array<string> = []): Promise<SignedEvent> {
  return await createRotate({
    seed,
    profile,
    did,
    prior: prior.event,
    snapshot: { members: [], deny },
  })
}

async function assertFolds(chain: Array<SignedEvent>) {
  const folded = await foldLog({ did, input: { chain, events: [] } })
  if (!folded.ok) throw new Error(folded.reason)
  return folded.head
}

describe('deviceRevokeIndex()', () => {
  test('returns the chain index of a rotate newly denying the subject', async () => {
    const plain = await rotate(inception)
    const revoke = await rotate(plain, [subject])
    const chain = [inception, plain, revoke]
    await assertFolds(chain)
    expect(await deviceRevokeIndex({ did, chain, subject })).toBe(2)
  })

  test('returns undefined for a plain rotate and for an inception alone', async () => {
    expect(await deviceRevokeIndex({ did, chain: [inception], subject })).toBeUndefined()
    expect(
      await deviceRevokeIndex({
        did,
        chain: [inception, await rotate(inception)],
        subject,
      }),
    ).toBeUndefined()
  })

  test('does not count a reset carrying the denial', async () => {
    const reset = await createReset({
      seed,
      profile,
      gen: 1,
      snapshot: { ...empty, deny: [subject] },
    })
    const chain = [inception, reset, await rotate(reset, [subject])]
    await assertFolds(chain)
    expect(await deviceRevokeIndex({ did, chain, subject })).toBeUndefined()
  })

  test('attributes a carried denial to the first rotate that introduced it', async () => {
    const revoke = await rotate(inception, [subject])
    const chain = [inception, revoke, await rotate(revoke, [subject])]
    await assertFolds(chain)
    expect(await deviceRevokeIndex({ did, chain, subject })).toBe(1)
  })

  test('finds re-denial after a reset denial is dropped', async () => {
    const reset = await createReset({
      seed,
      profile,
      gen: 1,
      snapshot: { ...empty, deny: [subject] },
    })
    const undeny = await rotate(reset)
    const chain = [inception, reset, undeny, await rotate(undeny, [subject])]
    await assertFolds(chain)
    expect(await deviceRevokeIndex({ did, chain, subject })).toBe(3)
  })

  test('returns the first revoke even when a later rotate re-denies the subject', async () => {
    const revoke = await rotate(inception, [subject])
    const undeny = await rotate(revoke)
    const chain = [inception, revoke, undeny, await rotate(undeny, [subject])]
    await assertFolds(chain)
    expect(await deviceRevokeIndex({ did, chain, subject })).toBe(1)
  })

  test('keeps did:key fragments distinct', async () => {
    const qualified = `${subject}#device`
    const chain = [inception, await rotate(inception, [qualified])]
    expect((await assertFolds(chain)).deny.has(qualified)).toBe(true)
    expect(await deviceRevokeIndex({ did, chain, subject })).toBeUndefined()
    expect(await deviceRevokeIndex({ did, chain, subject: qualified })).toBe(1)
  })

  test.each(peerForms)(
    'matches an equivalent peer DID ($denied)',
    async ({ denied, equivalent }) => {
      const chain = [inception, await rotate(inception, [denied])]
      await assertFolds(chain)
      expect(await deviceRevokeIndex({ did, chain, subject: equivalent })).toBe(1)
    },
  )

  test.each(peerForms)(
    'keeps the first revoke when a peer DID spelling changes ($denied)',
    async ({ denied, equivalent }) => {
      const revoke = await rotate(inception, [denied])
      const chain = [inception, revoke, await rotate(revoke, [equivalent])]
      await assertFolds(chain)
      expect(await deviceRevokeIndex({ did, chain, subject: equivalent })).toBe(1)
    },
  )

  test.each(peerForms)(
    'does not count a spelling change after a reset-carried denial ($denied)',
    async ({ denied, equivalent }) => {
      const reset = await createReset({
        seed,
        profile,
        gen: 1,
        snapshot: { ...empty, deny: [denied] },
      })
      const chain = [inception, reset, await rotate(reset, [equivalent])]
      await assertFolds(chain)
      expect(await deviceRevokeIndex({ did, chain, subject: equivalent })).toBeUndefined()
    },
  )

  test('refuses a non-critical inception skipped after the root inception', async () => {
    const skipped = await skippedInception(inception)
    const chain = [inception, skipped, await rotate(inception, [subject])]
    await assertFolds(chain)
    expect(await deviceRevokeIndex({ did, chain, subject })).toBeUndefined()
  })

  test('returns undefined if a later invalid event prevents the whole chain folding', async () => {
    const revoke = await rotate(inception, [subject])
    const invalid = { ...(await rotate(revoke, [subject])), sigs: [] }
    expect(
      await deviceRevokeIndex({ did, chain: [inception, revoke, invalid], subject }),
    ).toBeUndefined()
  })

  test('returns undefined for an empty chain or a different controller DID', async () => {
    expect(await deviceRevokeIndex({ did, chain: [], subject })).toBeUndefined()
    const otherDID = didFromInception(
      (await createInception({ seed: new Uint8Array(32).fill(2), profile })).event,
    )
    expect(
      await deviceRevokeIndex({
        did: otherDID,
        chain: [inception, await rotate(inception, [subject])],
        subject,
      }),
    ).toBeUndefined()
  })

  test('refuses chain revokes even when marked non-critical', async () => {
    const revoke = await rotate(inception, [subject])
    for (const crit of [true, false]) {
      const legacy = {
        ...revoke,
        event: { ...revoke.event, t: 'rev', crit },
      } as unknown as SignedEvent
      const chain = [inception, legacy, revoke]
      expect(await deviceRevokeIndex({ did, chain, subject })).toBeUndefined()
      await expect(
        async () => await createDeviceRevoke({ seed, profile, did, chain, subject }),
      ).rejects.toThrow()
    }
  })
})

describe('createDeviceRevoke()', () => {
  test('creates a valid revoke while preserving snapshot members and existing denials', async () => {
    const memberKey = (await createInception({ seed: new Uint8Array(32).fill(2), profile })).event
      .k[0]
    if (memberKey == null) throw new Error('Missing member key')
    const member: MemberEntry = {
      did: `did:key:${memberKey}`,
      key: memberKey,
      add: digestOf({ member: memberKey }),
      lease: 1_900_000_000,
    }
    const prior = await createRotate({
      seed,
      profile,
      did,
      prior: inception.event,
      snapshot: { members: [member], deny: ['did:key:zOtherDevice'] },
    })
    const chain = [inception, prior]
    const before = structuredClone(chain)
    const revoke = await createDeviceRevoke({ seed, profile, did, chain, subject })
    const head = await assertFolds([...chain, revoke])
    expect(await deviceRevokeIndex({ did, chain: [...chain, revoke], subject })).toBe(2)
    expect([...head.deny]).toEqual(['did:key:zOtherDevice', subject])
    expect([...head.members.values()]).toEqual([{ ...member, removed: false, effective: true }])
    expect(chain).toEqual(before)
  })

  test('creates a same-generation revoke after a reset', async () => {
    const chain = [inception, await createReset({ seed, profile, gen: 2 })]
    const revoke = await createDeviceRevoke({ seed, profile, did, chain, subject })
    expect((await assertFolds([...chain, revoke])).gen).toBe(2)
    expect(await deviceRevokeIndex({ did, chain: [...chain, revoke], subject })).toBe(2)
  })

  test('throws if the subject is already denied', async () => {
    const chain = [inception, await rotate(inception, [subject])]
    await expect(
      async () => await createDeviceRevoke({ seed, profile, did, chain, subject }),
    ).rejects.toThrow(/already denied/)
  })

  test.each(peerForms)(
    'throws if an equivalent peer DID is already denied ($denied)',
    async ({ denied, equivalent }) => {
      const chain = [inception, await rotate(inception, [denied])]
      await assertFolds(chain)
      await expect(
        async () => await createDeviceRevoke({ seed, profile, did, chain, subject: equivalent }),
      ).rejects.toThrow(/already denied/)
    },
  )

  test('refuses a skipped inception rather than building an invalid rotate', async () => {
    const chain = [inception, await skippedInception(inception)]
    await assertFolds(chain)
    await expect(
      async () => await createDeviceRevoke({ seed, profile, did, chain, subject }),
    ).rejects.toThrow(/root-only chain/)
  })

  test('throws if the chain does not fold', async () => {
    for (const chain of [[], [inception, { ...(await rotate(inception)), sigs: [] }]]) {
      await expect(
        async () => await createDeviceRevoke({ seed, profile, did, chain, subject }),
      ).rejects.toThrow(/empty log|invalid rotate/)
    }
  })
})

describe('deviceRevokeIndices()', () => {
  test('returns every revoke, including a re-revoke after a reset cleared the denial', async () => {
    const revoke = await rotate(inception, [subject])
    const reset = await createReset({ seed, profile, gen: 1 })
    const rerevoke = await rotate(reset, [subject])
    const chain = [inception, revoke, reset, rerevoke]
    await assertFolds(chain)
    expect(await deviceRevokeIndices({ did, chain, subject })).toEqual([1, 3])
    expect(await deviceRevokeIndex({ did, chain, subject })).toBe(1)
  })

  test('returns an empty array for a chain without a revoke and for an invalid chain', async () => {
    expect(
      await deviceRevokeIndices({
        did,
        chain: [inception, await rotate(inception)],
        subject,
      }),
    ).toEqual([])
    expect(
      await deviceRevokeIndices({
        did,
        chain: [inception, await skippedInception(inception)],
        subject,
      }),
    ).toEqual([])
  })
})
