import type { DIDMethodResolver } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { beforeEach, describe, expect, test, vi } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { createRevoke, type EpochEvent } from '../src/epoch-events.js'
import {
  createInception,
  createRotate,
  didFromInception,
  type EventCommon,
  type MemberEntry,
  type SignedEvent,
} from '../src/events.js'
import { foldLog, type KeyState } from '../src/fold.js'
import { clearFoldMemo } from '../src/fold-memo.js'
import * as history from '../src/history.js'
import { createMemoryLogStore, LOG_NOT_AUTHORITATIVE } from '../src/history.js'
import { encodeKey } from '../src/keys.js'
import type { ControllerLog } from '../src/log.js'
import { createControllerResolver, createControllerResolverWithin } from '../src/resolver.js'
import { EPOCH_SATURATED } from '../src/state-resolver.js'

// In a file of its own because `vi.mock` replaces the module for every test in the file: the fold is
// wrapped, not changed, so each test can count how often it actually ran.
vi.mock('../src/history.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/history.js')>()
  return { ...actual, authoritativeLogWithin: vi.fn(actual.authoritativeLogWithin) }
})

const folds = vi.mocked(history.authoritativeLogWithin)

const seed = new Uint8Array(32).fill(7)
const profile = 0
const icp = createInception(seed, profile)
const did = didFromInception(icp.event)

const memberPrivateKey = new Uint8Array(32).fill(23)
const memberKey = encodeKey(ed25519.getPublicKey(memberPrivateKey), 'EdDSA')
const member: MemberEntry = {
  did: `did:key:${memberKey}`,
  key: memberKey,
  add: digestOf('the add that admitted the member'),
  lease: 1_900_000_000,
}

function settle(prior: EventCommon, deny: Array<string> = []): SignedEvent {
  return createRotate({ seed, profile, did, prior, snapshot: { members: [member], deny } })
}

const rot = settle(icp.event)
const chain = [icp, rot]
const folded = foldLog(did, { chain, events: [] })
if (!folded.ok) throw new Error(`fixture does not fold: ${folded.reason}`)
const head: KeyState = folded.head

function revoke(target: string): SignedEvent<EpochEvent> {
  return createRevoke({
    signer: { root: { seed, profile } },
    did,
    head,
    parents: [head.epoch],
    target,
  })
}

const revA = revoke('did:key:zA')
const revB = revoke('did:key:zB')

/** A fresh copy each call, as a store hands back: the memo must key on content, not identity. */
function copy(log: ControllerLog): ControllerLog {
  return structuredClone(log)
}

/** The deny set, which this package's resolver always implements. */
async function denied(resolver: DIDMethodResolver): Promise<ReadonlySet<string>> {
  if (resolver.resolveDenySet === undefined) throw new Error('no resolveDenySet')
  return await resolver.resolveDenySet(did)
}

beforeEach(() => {
  clearFoldMemo()
  folds.mockClear()
})

describe('the fold memo', () => {
  test('an unchanged log is folded once, across resolver instances', async () => {
    const log: ControllerLog = { chain, events: [revA] }
    const first = createControllerResolver({ loadLog: async () => copy(log) })
    const deniedFirst = await denied(first)
    // A resolver per resolution, as kubun's engine builds them: still one fold.
    const second = createControllerResolver({ loadLog: async () => copy(log) })
    const deniedSecond = await denied(second)
    await second.resolve(did, {})
    expect(folds).toHaveBeenCalledTimes(1)
    expect(deniedFirst.has('did:key:zA')).toBe(true)
    expect([...deniedSecond]).toEqual([...deniedFirst])
  })

  test('a log that gains a revoke is folded again, and the revoke is observed', async () => {
    let log: ControllerLog = { chain, events: [] }
    const resolver = createControllerResolver({ loadLog: async () => copy(log) })
    expect((await denied(resolver)).has('did:key:zB')).toBe(false)
    expect((await denied(resolver)).has('did:key:zB')).toBe(false)
    expect(folds).toHaveBeenCalledTimes(1)
    log = { chain, events: [revB] }
    expect((await denied(resolver)).has('did:key:zB')).toBe(true)
    expect(folds).toHaveBeenCalledTimes(2)
  })

  test('a log carrying a capability-authorised event is never memoized', async () => {
    // Its signature no longer matches once `cap` is added, so the fold rejects the event and still
    // answers; what matters is that the answer is never kept.
    const withCap = { ...revB, event: { ...revB.event, cap: 'a capability' } }
    const log = { chain, events: [revA, withCap] } as unknown as ControllerLog
    const resolver = createControllerResolver({ loadLog: async () => copy(log) })
    await denied(resolver)
    await denied(resolver)
    expect(folds).toHaveBeenCalledTimes(2)
  })

  test('a memoized prefix is still refused once a longer log was accepted', async () => {
    const prefix: ControllerLog = { chain, events: [] }
    const longer: ControllerLog = {
      chain: [icp, rot, settle(rot.event, ['did:key:zLater'])],
      events: [],
    }

    // Memoize the prefix's fold against no memory.
    const plain = createControllerResolver({ loadLog: async () => copy(prefix) })
    await plain.resolve(did, {})
    await plain.resolve(did, {})
    expect(folds).toHaveBeenCalledTimes(1)

    let served = prefix
    const resolver = createControllerResolver({
      loadLog: async () => copy(served),
      history: createMemoryLogStore(),
    })
    // First encounter: nothing seen, so the memoized fold answers.
    await resolver.resolve(did, {})
    expect(folds).toHaveBeenCalledTimes(1)
    served = longer
    expect((await denied(resolver)).has('did:key:zLater')).toBe(true)
    // The prefix again: the memo holds a fold of it, but not against the longer log now seen.
    served = prefix
    await expect(resolver.resolve(did, {})).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
    await expect(resolver.resolve(did, {})).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
  })

  test('a memoized presentation withholding a seen revoke still answers with the revoke', async () => {
    const withheld: ControllerLog = { chain, events: [] }
    await createControllerResolver({ loadLog: async () => copy(withheld) }).resolve(did, {})

    let served: ControllerLog = { chain, events: [revA] }
    const resolver = createControllerResolver({
      loadLog: async () => copy(served),
      history: createMemoryLogStore(),
    })
    expect((await denied(resolver)).has('did:key:zA')).toBe(true)
    served = withheld
    expect((await denied(resolver)).has('did:key:zA')).toBe(true)
    expect((await denied(resolver)).has('did:key:zA')).toBe(true)
  })

  test('the store still skips its write when a memoized fold learned nothing new', async () => {
    const log: ControllerLog = { chain, events: [revA] }
    const store = createMemoryLogStore()
    const writes: Array<boolean> = []
    const resolver = createControllerResolver({
      loadLog: async () => copy(log),
      history: {
        get: (key) => store.get(key),
        merge: (key, update) =>
          store.merge(key, async (current) => {
            const next = await update(current)
            writes.push(next !== current)
            return next
          }),
      },
    })
    await resolver.resolve(did, {})
    await resolver.resolve(did, {})
    await resolver.resolve(did, {})
    expect(writes).toEqual([true, false, false])
    // The first against no memory, the second against the log it stored; the third is a hit.
    expect(folds).toHaveBeenCalledTimes(2)
  })

  test('lowered epoch limits never share an entry with the default fold', async () => {
    const log: ControllerLog = { chain, events: [revA, revB] }
    const plain = createControllerResolver({ loadLog: async () => copy(log) })
    expect((await denied(plain)).has('did:key:zB')).toBe(true)
    const lowered = createControllerResolverWithin(
      { loadLog: async () => copy(log) },
      { MAX_EPOCH_EVENTS: 1 },
    )
    await expect(lowered.resolve(did, {})).rejects.toThrow(EPOCH_SATURATED)
    await expect(lowered.resolve(did, {})).rejects.toThrow(EPOCH_SATURATED)
    expect(folds).toHaveBeenCalledTimes(3)
    // And the default entry is untouched by the lowered folds.
    await plain.resolve(did, {})
    expect(folds).toHaveBeenCalledTimes(3)
  })

  test('a refusal is never memoized', async () => {
    const forged = { ...revA, sigs: ['AA'] }
    const resolver = createControllerResolver({
      loadLog: async () => ({ chain: [icp, { ...rot, sigs: ['AA'] }], events: [forged] }),
    })
    await expect(resolver.resolve(did, {})).rejects.toThrow()
    await expect(resolver.resolve(did, {})).rejects.toThrow()
    expect(folds).toHaveBeenCalledTimes(2)
  })
})
