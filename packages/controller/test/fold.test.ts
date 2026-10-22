import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  keyTarget,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { foldLog, keyStateAt } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
/** The key an inception establishes: gen 0, derivation index 0. */
const authorityKey = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  const rot = createRotate({
    seed,
    profile: 0,
    did,
    prior: icp.event,
    snapshot: { members: [], deny: [] },
  })
  // A settlement on top of it: the second rotate's snapshot denies the stolen device.
  const denying = settle(did, rot.event, [stolen])
  return { did, icp, rot, denying }
}

function settle(did: string, prior: SignedEvent['event'], deny: Array<string>) {
  return createRotate({
    seed,
    profile: 0,
    did,
    prior,
    snapshot: { members: [], deny },
  })
}

describe('foldLog()', () => {
  test('folds inception alone', () => {
    const { did, icp } = build()
    const result = foldLog(did, { chain: [icp], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 0).keys).toEqual(icp.event.k)
    expect(at(result.states, 0).gen).toBe(0)
    expect(at(result.states, 0).seq).toBe(0)
  })

  test('an inception names the derivation index 0, whatever `s` it published', () => {
    // `keySeq` is the derivation index, and an inception opens the schedule at 0. The two numbers
    // coincide for every inception this package builds, so only a forged one can tell them apart —
    // and a forged one is buildable, because an inception is self-certifying: the DID is the hash
    // of the body, so a body with any `s` is a valid log for the DID it hashes to.
    const event = { ...createInception(seed, 0).event, s: 3 }
    const forgedDid = didFromInception(event)
    const forged = { event, sigs: signEvent(event, [authorityKey.privateKey]) }

    const result = foldLog(forgedDid, { chain: [forged], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 0).seq).toBe(3)
    expect(at(result.states, 0).keySeq).toBe(0)
    // The index really does name the published key, which is what the identity derives from.
    expect(at(result.states, 0).keys).toEqual([encodeKey(authorityKey.publicKey, 'EdDSA')])
  })

  test('applies a rotate, replacing the key set', () => {
    const { did, icp, rot } = build()
    const result = foldLog(did, { chain: [icp, rot], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 1).keys).toEqual(rot.event.k)
    expect(at(result.states, 1).keys).not.toEqual(icp.event.k)
  })

  test('a rotate replaces the deny set with its snapshot', () => {
    const { did, icp, rot, denying } = build()
    const result = foldLog(did, { chain: [icp, rot, denying], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect([...at(result.states, 2).deny]).toEqual([stolen])
    expect(at(result.states, 2).keys).toEqual(denying.event.k)
    // And the next settlement replaces it again: nothing before a rotate contributes.
    const cleared = settle(did, denying.event, [])
    const after = foldLog(did, { chain: [icp, rot, denying, cleared], events: [] })
    expect(after.ok && at(after.states, 3).deny.size).toBe(0)
  })

  test('rejects a log whose first event is not an inception', () => {
    const { did, rot } = build()
    const result = foldLog(did, { chain: [rot], events: [] })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/inception/)
  })

  test('rejects an inception whose hash is not the DID', () => {
    const { icp } = build()
    const result = foldLog('did:kokuin:zWRONG', { chain: [icp], events: [] })
    expect(result.ok).toBe(false)
  })

  test('rejects a sequence gap', () => {
    const { did, icp, rot } = build()
    const gapped = { ...rot, event: { ...rot.event, s: 5 } }
    const result = foldLog(did, { chain: [icp, gapped], events: [] })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.index).toBe(1)
  })

  test('rejects an event that does not chain to the previous digest', () => {
    const { did, icp, rot } = build()
    const orphan = { ...rot, event: { ...rot.event, p: 'zNOTTHEPRIOR' } }
    const result = foldLog(did, { chain: [icp, orphan], events: [] })
    expect(result.ok).toBe(false)
  })

  test('a reset increments the generation and clears the deny set', () => {
    const { did, icp, rot, denying } = build()
    // Anchored to the inception, not to the head.
    const reset = createReset(seed, 0, 1)
    const result = foldLog(did, { chain: [icp, rot, denying, reset], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 3).gen).toBe(1)
    expect(at(result.states, 3).seq).toBe(0)
    expect(at(result.states, 3).deny.size).toBe(0)
  })

  test('the inception seeds the agreement set', () => {
    const { did, icp } = build()
    const result = foldLog(did, { chain: [icp], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 0).agreement).toEqual(icp.event.ka)
  })

  test('a rotate replaces the agreement set', () => {
    const { did, icp, rot } = build()
    const result = foldLog(did, { chain: [icp, rot], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 1).agreement).toEqual(rot.event.ka)
    // Load-bearing: without it, a fold that ignored `ka` on rotate and carried the inception's
    // set forward would still pass every other assertion here.
    expect(at(result.states, 1).agreement).not.toEqual(icp.event.ka)
  })
})

describe('foldLog() and a revoke naming a key', () => {
  test('a key target lands in the deny set at that position and not before', () => {
    const { did, icp, rot } = build()
    // The key the inception established, which the rotate has since retired.
    const retired = keyTarget(at(icp.event.k, 0))
    const next = settle(did, rot.event, [retired])
    const result = foldLog(did, { chain: [icp, rot, next], events: [] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(at(result.states, 1).deny.has(retired)).toBe(false)
    expect(at(result.states, 2).deny.has(retired)).toBe(true)
    // It denies a key, not a holder: the key set the log publishes is the rotate's own.
    expect(at(result.states, 2).keys).toEqual(next.event.k)
  })

  test('a rotate cannot establish a key its own snapshot denies', () => {
    // `d` is author-written wire data, so a rotate could otherwise publish a key set and deny it in
    // the same event — leaving a head whose `k` resolves to nothing.
    const { did, icp, rot } = build()
    for (const key of [at(rot.event.k, 0), at(rot.event.ka, 0)]) {
      const selfDenying = settle(did, icp.event, [keyTarget(key)])
      const result = foldLog(did, { chain: [icp, selfDenying], events: [] })
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toMatch(/rotate establishes a denied key/)
    }

    // Control: the same rotate denying the keys it retires — the inception's — folds, so the
    // rejection is the collision and not the presence of `d`.
    const other = settle(did, icp.event, [
      keyTarget(at(icp.event.k, 0)),
      keyTarget(at(icp.event.ka, 0)),
    ])
    expect(foldLog(did, { chain: [icp, other], events: [] }).ok).toBe(true)
  })

  test('a denial of the committed next key leaves the generation no rotate that folds', () => {
    // The route to the same collision that needs no hand-edited event: a snapshot may deny the key
    // its own `n` commits to — it is in no key set yet — and the rotate that later reveals it either
    // keeps the denial (and establishes a denied key) or drops it (and drops a retirement the chain
    // has now seen the key for). Pre-rotation leaves no other key to reveal, so only a reset goes on.
    const { did, icp, rot } = build()
    const committedKey = encodeKey(
      deriveKeyPair(seed, authorityPath(0, 0, 3), 'EdDSA').publicKey,
      'EdDSA',
    )
    const committed = keyTarget(committedKey)
    const denied = settle(did, rot.event, [committed])
    expect(foldLog(did, { chain: [icp, rot, denied], events: [] }).ok).toBe(true)

    const keeping = settle(did, denied.event, [committed])
    expect(keeping.event.k).toEqual([committedKey])
    expect(foldLog(did, { chain: [icp, rot, denied, keeping], events: [] })).toMatchObject({
      ok: false,
      index: 3,
    })
    expect(foldReasonOf(did, [icp, rot, denied, keeping])).toMatch(
      /rotate establishes a denied key/,
    )
    const dropping = settle(did, denied.event, [])
    expect(foldLog(did, { chain: [icp, rot, denied, dropping], events: [] })).toEqual({
      ok: false,
      index: 3,
      reason: 'snapshot drops a retired key denial',
    })

    // Control: the identical rotate over a log whose snapshot denied a device DID instead. Same
    // signer, same commitment, same sequence — so the rejections above are the collision.
    const other = settle(did, rot.event, [stolen])
    expect(
      foldLog(did, { chain: [icp, rot, other, settle(did, other.event, [])], events: [] }).ok,
    ).toBe(true)
  })
})

function foldReasonOf(did: string, log: Array<SignedEvent>): string | undefined {
  const result = foldLog(did, { chain: log, events: [] })
  return result.ok ? undefined : result.reason
}

describe('keyStateAt()', () => {
  test('returns the state after the event at that position', () => {
    const { did, icp, rot, denying } = build()
    const result = foldLog(did, { chain: [icp, rot, denying], events: [] })
    expect(keyStateAt(result, 1)?.keys).toEqual(rot.event.k)
  })

  test('a device denied later is not denied at an earlier position', () => {
    const { did, icp, rot, denying } = build()
    const result = foldLog(did, { chain: [icp, rot, denying], events: [] })
    expect(keyStateAt(result, 1)?.deny.has(stolen)).toBe(false)
    expect(keyStateAt(result, 2)?.deny.has(stolen)).toBe(true)
  })

  test('returns undefined past the end of the log', () => {
    const { did, icp } = build()
    expect(keyStateAt(foldLog(did, { chain: [icp], events: [] }), 9)).toBeUndefined()
  })
})
