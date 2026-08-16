import { stringifyToken, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  keyTarget,
  type SignedEvent,
} from '../src/events.js'
import { foldLog, MAX_SKIPPED_SLACK, pruneDenySet, TOO_MANY_UNKNOWN_EVENTS } from '../src/fold.js'
import { createMemoryLogStore, LOG_NOT_AUTHORITATIVE } from '../src/history.js'
import { createControllerIdentityWithKey } from '../src/identity.js'
import { createControllerResolver } from '../src/resolver.js'
import { resolveBranches } from '../src/supersede.js'

// The 2026-08-15 design round. Each row is the attack that found the defect, kept with the
// assertion flipped to the fixed behaviour, and each carries the control that shows the guard under
// test is the one deciding.

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
  test('a forged cap-bearing branch is counted, not fatal', () => {
    const { inception, did } = build()
    // Two honest, conflicting revokes at position 1: a genuine fork, and the finding that matters.
    const honest = [
      [
        inception,
        createRevoke({
          seed,
          profile: 0,
          did,
          prior: inception.event,
          target: 'did:key:zA',
          keyPosition: { gen: 0, seq: 0 },
        }),
      ],
      [
        inception,
        createRevoke({
          seed,
          profile: 0,
          did,
          prior: inception.event,
          target: 'did:key:zB',
          keyPosition: { gen: 0, seq: 0 },
        }),
      ],
    ]

    // CONTROL — the fork alone. This is what must survive the attacker's presence.
    const control = resolveBranches(did, honest)
    expect(control.ok).toBe(false)
    if (control.ok) return
    expect(control.failure).toBe('duplicity')
    expect(control.unverified).toBe(0)

    // ATTACK — no key material at all. The inception is public, and a `cap`-bearing revoke reaches
    // the verifier path before any signature check, so `sigs` can be empty and `cap` arbitrary.
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
        cap: 'not-even-a-token',
      } as never,
      sigs: [],
    }
    const attacked = resolveBranches(did, [...honest, [inception, forged]])
    expect(attacked.ok).toBe(false)
    if (attacked.ok) return
    expect(attacked.failure, 'the fork is still reported').toBe('duplicity')
    expect(attacked.duplicity).toEqual(control.duplicity)
    // And the branch nobody signed is declared rather than dropped in silence.
    expect(attacked.unverified).toBe(1)
  })

  test('the forged branch cannot become the winner', () => {
    const { inception, did } = build()
    const honest = [inception, createRotate({ seed, profile: 0, did, prior: inception.event })]
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
        cap: 'not-even-a-token',
      } as never,
      sigs: [],
    }
    const result = resolveBranches(did, [honest, [inception, forged]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(honest)
    expect(result.unverified).toBe(1)
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
    const rot = createRotate({ seed, profile: 0, did, prior: inception.event })
    const log = [
      inception,
      rot,
      ...Array.from({ length: MAX_SKIPPED_SLACK + 1 }, (_, i) => padding(did, rot, i)),
    ]
    expect(foldLog(did, log).ok).toBe(true)
  })
})

describe('pruning a deny set cannot silently drop the rest of it', () => {
  test('pruneDenySet keeps what a hand-written snapshot loses', () => {
    const { inception, did } = build()
    const device = 'did:key:zDevice'
    const revoked = createRevoke({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      target: device,
      keyPosition: { gen: 0, seq: 0 },
    })
    const leaked = keyTarget(inception.event.k[0])
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: revoked.event,
      options: { keyPosition: { gen: 0, seq: 0 } },
    })
    const denied = createRevoke({
      seed,
      profile: 0,
      did,
      prior: rot.event,
      target: leaked,
      keyPosition: { gen: 0, seq: 1 },
    })
    const folded = foldLog(did, [inception, revoked, rot, denied])
    expect(folded.ok).toBe(true)
    if (!folded.ok) return
    const state = folded.states[3]
    expect([...state.deny].sort()).toEqual([device, leaked].sort())

    // THE HAZARD — a caller who reads `denySnapshot` as "also deny this" writes one entry and
    // silently un-retires the leaked key. Nothing rejects it: this is a legal event.
    const byHand = createRotate({
      seed,
      profile: 0,
      did,
      prior: denied.event,
      options: {
        keyPosition: { gen: state.keyGen, seq: state.keySeq },
        denySnapshot: [device],
      },
    })
    const lost = foldLog(did, [inception, revoked, rot, denied, byHand])
    expect(lost.ok).toBe(true)
    if (!lost.ok) return
    expect(lost.states[4].deny.has(leaked), 'the leaked key is no longer denied').toBe(false)

    // THE FIX — built from the fold's own answer, so only what was named is dropped.
    const pruned = createRotate({
      seed,
      profile: 0,
      did,
      prior: denied.event,
      options: {
        keyPosition: { gen: state.keyGen, seq: state.keySeq },
        denySnapshot: pruneDenySet(state, [device]),
      },
    })
    const kept = foldLog(did, [inception, revoked, rot, denied, pruned])
    expect(kept.ok).toBe(true)
    if (!kept.ok) return
    expect(kept.states[4].deny.has(leaked)).toBe(true)
    expect(kept.states[4].deny.has(device)).toBe(false)
  })
})

describe('signing as the profile without the root seed', () => {
  test('the current authority key alone produces a verifiable token', async () => {
    const { inception, did } = build()
    const log = [inception, createRotate({ seed, profile: 0, did, prior: inception.event })]
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
    const full = [
      inception,
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        target: device,
        keyPosition: { gen: 0, seq: 0 },
      }),
    ]
    const truncated = [inception]

    const resolver = await resolverOver([full, truncated])
    expect([...(await denySet(resolver, did))].includes(device)).toBe(true)
    // The peer now serves the prefix that stops just before the revoke. It folds, it verifies, and
    // its deny set is missing exactly the entry that matters.
    await expect(resolver.resolveDenySet?.(did)).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
  })

  test('CONTROL — the same log served again is not a truncation', async () => {
    // The commonest call there is. Comparing by array identity rather than by folded head would
    // reject this, which is a resolver that stops working after its first answer.
    const { inception, did } = build()
    const full = [
      inception,
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        target: 'did:key:zThief',
        keyPosition: { gen: 0, seq: 0 },
      }),
    ]
    const resolver = await resolverOver([full, [...full]])
    await resolver.resolveDenySet?.(did)
    expect([...(await denySet(resolver, did))]).toEqual(['did:key:zThief'])
  })

  test('CONTROL — a log carried further is accepted', async () => {
    const { inception, did } = build()
    const first = [inception]
    const later = [
      inception,
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: inception.event,
        target: 'did:key:zThief',
        keyPosition: { gen: 0, seq: 0 },
      }),
    ]
    const resolver = await resolverOver([first, later])
    await resolver.resolveDenySet?.(did)
    expect([...(await denySet(resolver, did))]).toEqual(['did:key:zThief'])
  })

  test('CONTROL — a superseding rotate is accepted although its sequence is lower', async () => {
    // The case a high-water mark over `(gen, seq)` would have rejected, and the reason this guard
    // is a branch comparison instead: a thief holding a current key appends revokes until their
    // branch is long, and the owner's recovering rotate — which supersedes all of it — sits far
    // behind it in sequence. Refusing that would brick the profile at the moment it is rescued.
    const { inception, did } = build()
    let thiefBranch: Array<SignedEvent> = [inception]
    let prior: SignedEvent = inception
    for (let i = 0; i < 5; i++) {
      const rev: SignedEvent = createRevoke({
        seed,
        profile: 0,
        did,
        prior: prior.event,
        target: `did:key:zVictim${i}`,
        keyPosition: {
          gen: 0,
          seq: 0,
        },
      })
      thiefBranch = [...thiefBranch, rev]
      prior = rev
    }
    const recovery = [inception, createRotate({ seed, profile: 0, did, prior: inception.event })]

    const resolver = await resolverOver([thiefBranch, recovery])
    const first = await resolver.resolveDenySet?.(did)
    expect(first?.size).toBe(5)
    // The recovering rotate is at seq 1 against a seen head at seq 5, and it wins.
    expect((await resolver.resolveDenySet?.(did))?.size).toBe(0)
  })
})

describe('the truncation guard fails closed when the stored log needs a verifier', () => {
  // A management-tier log folds only with a `verifyCapability`. If a later resolution has no verifier
  // configured, the stored (full) log fails to fold — for want of the verifier, not because anything
  // about it changed. Treating that as "no memory" accepted whatever prefix was served next, which
  // disables the truncation guard for exactly the profiles that use the management tier: a peer
  // serving a prefix that stops before the cap-authorised `rev` denying their device wins, because
  // the fuller log this party already holds is the one that could not be folded.
  const cSeed = new Uint8Array(32).fill(7)
  const delegateSeed = new Uint8Array(32).fill(3)
  const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
  const cap = 'eyJ.delegated.revoke'
  const authorised = {
    authorised: true as const,
    audienceKey: {
      alg: 'EdDSA' as const,
      publicKey: deriveKeyPair(delegateSeed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
    },
  }

  function capLog() {
    const icp = createInception(cSeed, 0)
    const did = didFromInception(icp.event)
    // Signed by the delegate, so only the capability it carries authorises it — foldable only async
    // and only with a verifier.
    const rev = createRevoke({
      seed: delegateSeed,
      profile: 0,
      did,
      prior: icp.event,
      target: device,
      keyPosition: { gen: 0, seq: 0 },
      cap,
    })
    return { icp, did, full: [icp, rev] as Array<SignedEvent> }
  }

  test('a prefix served to a verifier-less reader is refused, not accepted as no memory', async () => {
    const { icp, did, full } = capLog()
    const store = createMemoryLogStore()

    // Stored while a verifier was configured: the management-tier log folds and is remembered.
    const configured = createControllerResolver({
      loadLog: async () => full,
      history: store,
      verifyCapability: async () => authorised,
    })
    expect([...(await denySet(configured, did))]).toEqual([device])

    // Same store, a reader with no verifier now, served the prefix that stops before the cap-revoke.
    // The prefix folds cleanly without a verifier; the fuller stored log does not.
    const unconfigured = createControllerResolver({
      loadLog: async () => [icp],
      history: store,
    })
    await expect(unconfigured.resolveDenySet?.(did)).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
  })

  test('CONTROL — the same truncation is refused with a verifier too, so the fix only aligns the two', async () => {
    const { icp, did, full } = capLog()
    const store = createMemoryLogStore()
    const verifyCapability = async () => authorised

    const first = createControllerResolver({
      loadLog: async () => full,
      history: store,
      verifyCapability,
    })
    expect([...(await denySet(first, did))]).toEqual([device])

    // A reader that still has the verifier refuses the same prefix — the branch comparison, not the
    // missing verifier, is what rejects it. The no-verifier path now matches this.
    const second = createControllerResolver({
      loadLog: async () => [icp],
      history: store,
      verifyCapability,
    })
    await expect(second.resolveDenySet?.(did)).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
  })
})
