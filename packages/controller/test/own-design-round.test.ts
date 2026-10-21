import { stringifyToken, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRotate,
  didFromInception,
  keyTarget,
  type MemberEntry,
  type SignedEvent,
} from '../src/events.js'
import { foldLog, MAX_SKIPPED_SLACK, snapshotOf, TOO_MANY_UNKNOWN_EVENTS } from '../src/fold.js'
import { createMemoryLogStore, LOG_NOT_AUTHORITATIVE } from '../src/history.js'
import { createControllerIdentityWithKey } from '../src/identity.js'
import { encodeKey } from '../src/keys.js'
import { createControllerResolver } from '../src/resolver.js'
import { resolveBranches } from '../src/supersede.js'

// The 2026-08-15 design round. Each row is the attack that found the defect, kept with the
// assertion flipped to the fixed behaviour, and each carries the control that shows the guard under
// test is the one deciding.

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const seed = new Uint8Array(32).fill(11)

/** The member is optional on the interface; every controller resolver publishes one. */
async function denySet(
  resolver: { resolveDenySet?: (did: string) => Promise<ReadonlySet<string>> },
  did: string,
): Promise<ReadonlySet<string>> {
  if (resolver.resolveDenySet == null) {
    throw new Error('resolver publishes no deny set')
  }
  return await resolver.resolveDenySet(did)
}

function build() {
  const inception = createInception(seed, 0)
  return { inception, did: didFromInception(inception.event) }
}

/** A rotate on `prior` whose snapshot denies `deny` and carries `members`. */
function settle(
  did: string,
  prior: SignedEvent['event'],
  deny: Array<string>,
  members: Array<MemberEntry> = [],
): SignedEvent {
  return createRotate({ seed, profile: 0, did, prior, options: { snapshot: { members, deny } } })
}

/** An event of a type no version understands, unsigned, declaring itself skippable. */
function padding(did: string, prior: SignedEvent, index: number): SignedEvent {
  return {
    event: {
      v: 1,
      t: `pad-${index}` as never,
      i: did,
      g: prior.event.g,
      s: prior.event.s + 1,
      p: digestOf(prior.event),
      crit: false,
    },
    sigs: [],
  }
}

describe('a keyless peer cannot switch duplicity detection off', () => {
  test('a forged unsigned branch is filtered, not fatal', () => {
    const { inception, did } = build()
    // Two honest, conflicting settlements at position 1: a genuine fork, and the finding that
    // matters.
    const honest = [
      [inception, settle(did, inception.event, ['did:key:zA'])],
      [inception, settle(did, inception.event, ['did:key:zB'])],
    ]

    // CONTROL — the fork alone. This is what must survive the attacker's presence.
    const control = resolveBranches(did, honest)
    expect(control.ok).toBe(false)
    if (control.ok) return
    expect(control.failure).toBe('duplicity')

    // ATTACK — no key material at all. The inception is public, so a peer can append an event with
    // no signatures to a copy of it and present the result as a branch.
    const forged: SignedEvent = {
      event: {
        v: 1,
        t: 'rev',
        i: did,
        g: 0,
        s: 1,
        p: digestOf(inception.event),
        crit: true,
        x: 'did:key:zC',
      } as never,
      sigs: [],
    }
    const attacked = resolveBranches(did, [...honest, [inception, forged]])
    expect(attacked.ok).toBe(false)
    if (attacked.ok) return
    expect(attacked.failure, 'the fork is still reported').toBe('duplicity')
    expect(attacked.duplicity).toEqual(control.duplicity)
  })

  test('the forged branch cannot become the winner', () => {
    const { inception, did } = build()
    const honest = [
      inception,
      createRotate({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        options: { snapshot: { members: [], deny: [] } },
      }),
    ]
    const forged: SignedEvent = {
      event: {
        v: 1,
        t: 'rev',
        i: did,
        g: 0,
        s: 1,
        p: digestOf(inception.event),
        crit: true,
        x: 'did:key:zC',
      } as never,
      sigs: [],
    }
    const result = resolveBranches(did, [honest, [inception, forged]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(honest)
  })
})

describe('unsigned padding cannot grow a log without limit', () => {
  test('a padded log is refused, and the same log within budget is not', () => {
    const { inception, did } = build()

    // CONTROL — padding within the slack folds, which is what keeps a v1 verifier able to read a
    // later version's non-critical events.
    const within = [
      inception,
      ...Array.from({ length: MAX_SKIPPED_SLACK }, (_, i) => padding(did, inception, i)),
    ]
    const controlResult = foldLog(did, within)
    expect(controlResult.ok, 'padding within the slack still folds').toBe(true)

    // ATTACK — the same events, past the budget. Before this bound, 500 of them folded clean.
    const beyond = [
      inception,
      ...Array.from({ length: MAX_SKIPPED_SLACK + 2 }, (_, i) => padding(did, inception, i)),
    ]
    const attacked = foldLog(did, beyond)
    expect(attacked.ok).toBe(false)
    if (attacked.ok) return
    expect(attacked.reason).toBe(TOO_MANY_UNKNOWN_EVENTS)
  })

  test('the budget grows with the log’s own real length', () => {
    // The ceiling is proportional to work the verifier was going to do anyway, so a long honest log
    // is not held to the same absolute count as a two-event one.
    const { inception, did } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const log = [
      inception,
      rot,
      ...Array.from({ length: MAX_SKIPPED_SLACK + 1 }, (_, i) => padding(did, rot, i)),
    ]
    expect(foldLog(did, log).ok).toBe(true)
  })
})

describe('carrying a state forward cannot silently drop the rest of it', () => {
  test('snapshotOf keeps what a hand-written snapshot loses', () => {
    const { inception, did } = build()
    const device = 'did:key:zDevice'
    const memberKey = encodeKey(
      deriveKeyPair(new Uint8Array(32).fill(12), authorityPath(0, 0, 0), 'EdDSA').publicKey,
      'EdDSA',
    )
    const member: MemberEntry = {
      did: `did:key:${memberKey}`,
      key: memberKey,
      add: digestOf('the add that admitted it'),
      lease: 1_900_000_000,
    }
    const leaked = keyTarget(at(inception.event.k, 0))
    const settled = settle(did, inception.event, [device, leaked], [member])
    const folded = foldLog(did, [inception, settled])
    expect(folded.ok).toBe(true)
    if (!folded.ok) return
    const state = at(folded.states, 1)
    expect([...state.deny].sort()).toEqual([device, leaked].sort())

    // THE HAZARD — a caller who reads the snapshot as "also do this" writes only what they mean to
    // change. The checkpointed retirement cannot be lost that way (the fold refuses the rotate), but
    // the member and every other denial can: this is a legal event that dismisses the management
    // tier and un-revokes nothing it meant to.
    const byHand = settle(did, settled.event, [leaked])
    const lost = foldLog(did, [inception, settled, byHand])
    expect(lost.ok).toBe(true)
    if (!lost.ok) return
    expect(at(lost.states, 2).members.size, 'the member is no longer in the set').toBe(0)
    const forgotten = settle(did, settled.event, [device])
    expect(foldLog(did, [inception, settled, forgotten])).toMatchObject({
      ok: false,
      reason: 'snapshot drops a retired key denial',
    })

    // THE FIX — built from the fold's own answer, so only what was named is dropped.
    const pruned = createRotate({
      seed,
      profile: 0,
      did,
      prior: settled.event,
      options: { snapshot: snapshotOf(state, { deny: [device] }) },
    })
    const kept = foldLog(did, [inception, settled, pruned])
    expect(kept.ok).toBe(true)
    if (!kept.ok) return
    expect(at(kept.states, 2).deny.has(leaked)).toBe(true)
    expect(at(kept.states, 2).deny.has(device)).toBe(false)
    expect(at(kept.states, 2).members.get(member.add)).toEqual({
      ...member,
      removed: false,
      effective: true,
    })
  })
})

describe('signing as the profile without the root seed', () => {
  test('the current authority key alone produces a verifiable token', async () => {
    const { inception, did } = build()
    const log = [
      inception,
      createRotate({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        options: { snapshot: { members: [], deny: [] } },
      }),
    ]
    // What a device is given: one private key, no seed, no profile index.
    const current = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')

    const identity = createControllerIdentityWithKey({ privateKey: current.privateKey, log })
    expect(identity.id).toBe(did)
    const token = stringifyToken(await identity.signToken({ hello: 'world' }))
    const resolver = createControllerResolver({ loadLog: async () => log })
    const verified = await verifyToken(token, { methods: [resolver] })
    expect(verified.payload.iss).toBe(did)

    // CONTROL — a key the head does not publish is refused at construction, not at verification.
    const retired = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
    expect(() => createControllerIdentityWithKey({ privateKey: retired.privateKey, log })).toThrow(
      /not one of the current authority keys/,
    )
  })
})

describe('a truncated log is refused when one further along has been seen', () => {
  async function resolverOver(logs: Array<Array<SignedEvent>>) {
    let call = 0
    return createControllerResolver({
      history: createMemoryLogStore(),
      loadLog: async () => logs[Math.min(call++, logs.length - 1)],
    })
  }

  test('a prefix served after the full log is refused', async () => {
    const { inception, did } = build()
    const device = 'did:key:zThief'
    const full = [inception, settle(did, inception.event, [device])]
    const truncated = [inception]

    const resolver = await resolverOver([full, truncated])
    expect([...(await denySet(resolver, did))].includes(device)).toBe(true)
    // The peer now serves the prefix that stops just before the denying rotate. It folds, it verifies, and
    // its deny set is missing exactly the entry that matters.
    await expect(resolver.resolveDenySet?.(did)).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
  })

  test('CONTROL — the same log served again is not a truncation', async () => {
    // The commonest call there is. Comparing by array identity rather than by folded head would
    // reject this, which is a resolver that stops working after its first answer.
    const { inception, did } = build()
    const full = [inception, settle(did, inception.event, ['did:key:zThief'])]
    const resolver = await resolverOver([full, [...full]])
    await resolver.resolveDenySet?.(did)
    expect([...(await denySet(resolver, did))]).toEqual(['did:key:zThief'])
  })

  test('CONTROL — a log carried further is accepted', async () => {
    const { inception, did } = build()
    const first = [inception]
    const later = [inception, settle(did, inception.event, ['did:key:zThief'])]
    const resolver = await resolverOver([first, later])
    await resolver.resolveDenySet?.(did)
    expect([...(await denySet(resolver, did))]).toEqual(['did:key:zThief'])
  })
})
