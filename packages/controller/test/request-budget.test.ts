import { ed25519 } from '@noble/curves/ed25519.js'
import { beforeEach, describe, expect, test, vi } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { TOO_MANY_FAILED_SIGNATURES } from '../src/epoch.js'
import { createRevoke, type EpochEvent } from '../src/epoch-events.js'
import {
  createInception,
  createRotate,
  didFromInception,
  type MemberEntry,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { authoritativeLog, createMemoryLogStore } from '../src/history.js'
import { encodeKey } from '../src/keys.js'
import { MAX_FAILED_SIGNATURES } from '../src/limits.js'
import type { ControllerLog } from '../src/log.js'
import { createControllerResolver } from '../src/resolver.js'

// Counts every signature check the fold asks for, so "not re-verified" is asserted on work done
// rather than on elapsed time.
const checks = vi.hoisted(() => ({ count: 0 }))
vi.mock('../src/epoch-events.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/epoch-events.js')>()
  return {
    ...actual,
    verifyEpochSignature: (...args: Parameters<typeof actual.verifyEpochSignature>) => {
      checks.count++
      return actual.verifyEpochSignature(...args)
    },
  }
})

const seed = new Uint8Array(32).fill(5)
const profile = 0
const inception = createInception(seed, profile)
const did = didFromInception(inception.event)

const memberSecret = new Uint8Array(32).fill(21)
const memberKey = encodeKey(ed25519.getPublicKey(memberSecret), 'EdDSA')
const member: MemberEntry = {
  did: `did:key:${memberKey}`,
  key: memberKey,
  add: digestOf('the add that admitted the member'),
  lease: 1_900_000_000,
}
const rot = createRotate({
  seed,
  profile,
  did,
  prior: inception.event,
  snapshot: { members: [member], deny: [] },
})
const chain: Array<SignedEvent> = [inception, rot]
const folded = foldLog(did, { chain, events: [] })
if (!folded.ok) {
  throw new Error(`fixture chain does not fold: ${folded.reason}`)
}
const head = folded.head

function revoke(target: string, parents: Array<string> = [head.epoch]): SignedEvent<EpochEvent> {
  return createRevoke({
    did,
    head,
    parents,
    signer: { member: { privateKey: memberSecret, add: member.add } },
    target,
  })
}

// Signed once: deriving the root key per forgery made fixture setup, not the fold, the slow part.
const template = createRevoke({
  did,
  head,
  parents: [head.epoch],
  signer: { root: { seed, profile } },
  target: 'did:key:zForged',
})

/** A root-shaped revoke under a signature that does not verify: a forgery no key went into. */
function forged(i: number): SignedEvent<EpochEvent> {
  return { event: { ...template.event, x: `did:key:zForgedOther${i}` }, sigs: template.sigs }
}

function shuffled<T>(items: Array<T>, salt: number): Array<T> {
  return items
    .map((item, i) => ({ item, rank: digestOf(`${salt}:${i}`) }))
    .sort((x, y) => (x.rank < y.rank ? -1 : 1))
    .map(({ item }) => item)
}

const honest = [revoke('did:key:zOne'), revoke('did:key:zTwo')]

beforeEach(() => {
  checks.count = 0
})

describe('the failed-signature budget', () => {
  test('a presentation whose forgeries exceed the budget is refused, whatever its order', () => {
    const forgeries = Array.from({ length: MAX_FAILED_SIGNATURES + 1 }, (_, i) => forged(i))
    for (const salt of [1, 2, 3, 4]) {
      const events = shuffled([...honest, ...forgeries], salt)
      expect(foldLog(did, { chain, events })).toEqual({
        ok: false,
        reason: TOO_MANY_FAILED_SIGNATURES,
        index: -1,
      })
    }
  })

  test('the refusal stops checking once the budget is spent', () => {
    const forgeries = Array.from({ length: 4 * MAX_FAILED_SIGNATURES }, (_, i) => forged(i))
    expect(foldLog(did, { chain, events: forgeries }).ok).toBe(false)
    expect(checks.count).toBe(MAX_FAILED_SIGNATURES + 1)
  })

  test('forgeries up to the budget still fold, each refused', () => {
    const forgeries = Array.from({ length: MAX_FAILED_SIGNATURES }, (_, i) => forged(i))
    const result = foldLog(did, { chain, events: shuffled([...honest, ...forgeries], 7) })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.applied).toHaveLength(honest.length)
    expect(result.rejected).toBe(MAX_FAILED_SIGNATURES)
  })

  test('a copy is charged once per distinct signature list, and per signature it carries', () => {
    const [one] = honest as [SignedEvent<EpochEvent>]
    // `!` sorts before every base64url character, so these lists are checked before the genuine one.
    const bad = (i: number) => ({ event: one.event, sigs: [`!${String(i).padStart(4, '0')}`] })
    // Distinct forged lists sorting before the genuine one are each checked and charged.
    const distinct = Array.from({ length: MAX_FAILED_SIGNATURES + 1 }, (_, i) => bad(i))
    expect(foldLog(did, { chain, events: [one, ...distinct] }).ok).toBe(false)
    // One forged list repeated is checked once.
    const repeated = Array.from({ length: 4 * MAX_FAILED_SIGNATURES }, () => bad(0))
    expect(foldLog(did, { chain, events: [one, ...repeated] }).ok).toBe(true)
    // A copy carrying several signatures is charged for each.
    const wide = (i: number) => ({ ...forged(i), sigs: Array.from({ length: 16 }, () => 'AAAA') })
    const few = Array.from({ length: MAX_FAILED_SIGNATURES / 16 }, (_, i) => wide(i))
    expect(foldLog(did, { chain, events: few }).ok).toBe(true)
    expect(foldLog(did, { chain, events: [...few, forged(999)] }).ok).toBe(false)
  })
})

describe('held memory', () => {
  const stored = authoritativeLog({
    did,
    loaded: { chain, events: honest },
    seen: undefined,
    context: 'test',
  }).log

  test('a refused presentation leaves memory as it was', async () => {
    const store = createMemoryLogStore()
    const loaded: { log: ControllerLog } = { log: { chain, events: honest } }
    const resolver = createControllerResolver({
      loadLog: async () => loaded.log,
      history: store,
    })
    await resolver.resolve(did, {})
    const before = await store.get(did)
    const forgeries = Array.from({ length: MAX_FAILED_SIGNATURES + 1 }, (_, i) => forged(i))
    loaded.log = { chain, events: [revoke('did:key:zThree'), ...forgeries] }
    await expect(resolver.resolve(did, {})).rejects.toThrow(TOO_MANY_FAILED_SIGNATURES)
    expect(await store.get(did)).toBe(before)
  })

  test('held events are folded without checking their signatures again', () => {
    checks.count = 0
    const nothingNew = authoritativeLog({
      did,
      loaded: { chain, events: [] },
      seen: stored,
      context: 'test',
    })
    expect(nothingNew.result.applied).toHaveLength(honest.length)
    expect(checks.count).toBe(0)

    // Presented again, a held event still costs nothing: the held copy answers for it.
    authoritativeLog({ did, loaded: { chain, events: honest }, seen: stored, context: 'test' })
    expect(checks.count).toBe(0)

    // Only what is new is checked.
    const fresh = revoke('did:key:zThree')
    const grown = authoritativeLog({
      did,
      loaded: { chain, events: [fresh] },
      seen: stored,
      context: 'test',
    })
    expect(checks.count).toBe(1)
    expect(grown.result.applied).toContain(digestOf(fresh.event))
  })

  test('forged copies of a held event are not charged', () => {
    const [one] = honest as [SignedEvent<EpochEvent>]
    const copies = Array.from({ length: 2 * MAX_FAILED_SIGNATURES }, (_, i) => ({
      event: one.event,
      sigs: [`A${i}`],
    }))
    const result = authoritativeLog({
      did,
      loaded: { chain, events: copies },
      seen: stored,
      context: 'test',
    })
    expect(checks.count).toBe(0)
    expect(result.log.events).toEqual(stored.events)
  })

  test('a held event the stored chain no longer anchors is not trusted', () => {
    const settled = createRotate({
      seed,
      profile,
      did,
      prior: rot.event,
      snapshot: { members: [member], deny: [] },
    })
    const result = authoritativeLog({
      did,
      loaded: { chain: [...chain, settled], events: [] },
      seen: stored,
      context: 'test',
    })
    expect(result.result.applied).toEqual([])
    expect(result.log.events).toEqual([])
  })

  test('nothing new answers with the stored log itself, so a store can skip the write', () => {
    const same = authoritativeLog({
      did,
      loaded: { chain, events: [...honest].reverse() },
      seen: stored,
      context: 'test',
    })
    expect(same.log).toBe(stored)
    // A copy with equal content, as a store re-reads it, is recognised too.
    const reread = JSON.parse(JSON.stringify(stored)) as ControllerLog
    expect(
      authoritativeLog({ did, loaded: { chain, events: [] }, seen: reread, context: 'test' }).log,
    ).toBe(reread)
    const grown = authoritativeLog({
      did,
      loaded: { chain, events: [revoke('did:key:zThree')] },
      seen: stored,
      context: 'test',
    })
    expect(grown.log).not.toBe(stored)
  })

  test('the memory store skips the write when the update returns the current log', async () => {
    const store = createMemoryLogStore()
    const first = await store.merge(did, async () => stored)
    const again = await store.merge(did, async (current) => current ?? stored)
    expect(again).toBe(first)
    expect(await store.get(did)).toBe(first)
  })
})
