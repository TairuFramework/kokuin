import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  encodeKey,
  keyTarget,
  signEvent,
} from '../src/events.js'
import { foldLog, keyStateAt } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
/** The key an inception establishes: gen 0, derivation index 0. */
const authorityKey = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  const rot = createRotate(seed, 0, did, icp.event)
  // The rotate established the active key at its own position (gen 0, seq 1), so that is the
  // keyPosition the revoke signs with — see Amendment A.
  const rev = createRevoke(seed, 0, did, rot.event, stolen, { gen: 0, seq: 1 })
  return { did, icp, rot, rev }
}

describe('foldLog()', () => {
  test('folds inception alone', () => {
    const { did, icp } = build()
    const result = foldLog(did, [icp])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[0].keys).toEqual(icp.event.k)
    expect(result.states[0].gen).toBe(0)
    expect(result.states[0].seq).toBe(0)
  })

  test('an inception names the derivation index 0, whatever `s` it published', () => {
    // `keySeq` is the derivation index, and an inception opens the schedule at 0. The two numbers
    // coincide for every inception this package builds, so only a forged one can tell them apart —
    // and a forged one is buildable, because an inception is self-certifying: the DID is the hash
    // of the body, so a body with any `s` is a valid log for the DID it hashes to.
    const event = { ...createInception(seed, 0).event, s: 3 }
    const forgedDid = didFromInception(event)
    const forged = { event, sigs: signEvent(event, [authorityKey.privateKey]) }

    const result = foldLog(forgedDid, [forged])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[0].seq).toBe(3)
    expect(result.states[0].keySeq).toBe(0)
    // The index really does name the published key, which is what the identity derives from.
    expect(result.states[0].keys).toEqual([encodeKey(authorityKey.publicKey, 'EdDSA')])
  })

  test('applies a rotate, replacing the key set', () => {
    const { did, icp, rot } = build()
    const result = foldLog(did, [icp, rot])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].keys).toEqual(rot.event.k)
    expect(result.states[1].keys).not.toEqual(icp.event.k)
  })

  test('applies a revoke, adding to the deny set without touching the keys', () => {
    const { did, icp, rot, rev } = build()
    const result = foldLog(did, [icp, rot, rev])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[2].deny.has(stolen)).toBe(true)
    expect(result.states[2].keys).toEqual(rot.event.k)
  })

  test('rejects a log whose first event is not an inception', () => {
    const { did, rot } = build()
    const result = foldLog(did, [rot])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/inception/)
  })

  test('rejects an inception whose hash is not the DID', () => {
    const { icp } = build()
    const result = foldLog('did:kokuin:zWRONG', [icp])
    expect(result.ok).toBe(false)
  })

  test('rejects a sequence gap', () => {
    const { did, icp, rot } = build()
    const gapped = { ...rot, event: { ...rot.event, s: 5 } }
    const result = foldLog(did, [icp, gapped])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.index).toBe(1)
  })

  test('rejects an event that does not chain to the previous digest', () => {
    const { did, icp, rot } = build()
    const orphan = { ...rot, event: { ...rot.event, p: 'zNOTTHEPRIOR' } }
    const result = foldLog(did, [icp, orphan])
    expect(result.ok).toBe(false)
  })

  test('a reset increments the generation and clears the deny set', () => {
    const { did, icp, rot, rev } = build()
    // Anchored to the inception, not to the head — see Amendment A.
    const reset = createReset(seed, 0, 1)
    const result = foldLog(did, [icp, rot, rev, reset])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[3].gen).toBe(1)
    expect(result.states[3].seq).toBe(0)
    expect(result.states[3].deny.size).toBe(0)
  })

  test('the inception seeds the agreement set', () => {
    const { did, icp } = build()
    const result = foldLog(did, [icp])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[0].agreement).toEqual(icp.event.ka)
  })

  test('a rotate replaces the agreement set', () => {
    const { did, icp, rot } = build()
    const result = foldLog(did, [icp, rot])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].agreement).toEqual(rot.event.ka)
    // Load-bearing: without it, a fold that ignored `ka` on rotate and carried the inception's
    // set forward would still pass every other assertion here.
    expect(result.states[1].agreement).not.toEqual(icp.event.ka)
  })

  test('a revoke carries the agreement set forward unchanged', () => {
    const { did, icp, rot, rev } = build()
    const result = foldLog(did, [icp, rot, rev])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    // The revoke establishes no agreement key, so the set is still the rotate's — Amendment A.
    expect(result.states[2].agreement).toEqual(rot.event.ka)
  })
})

describe('foldLog() and a revoke naming a key', () => {
  test('a key target lands in the deny set at that position and not before', () => {
    const { did, icp, rot } = build()
    // The key the inception established, which the rotate has since retired.
    const retired = keyTarget(icp.event.k[0])
    const rev = createRevoke(seed, 0, did, rot.event, retired, { gen: 0, seq: 1 })
    const result = foldLog(did, [icp, rot, rev])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(retired)).toBe(false)
    expect(result.states[2].deny.has(retired)).toBe(true)
    // It denies a key, not a holder: the key set the log publishes is untouched.
    expect(result.states[2].keys).toEqual(rot.event.k)
  })

  test('a key the profile currently publishes cannot be denied', () => {
    const { did, icp, rot } = build()
    // The rotate's own key — the head's `k` at the position the revoke sits at.
    const current = keyTarget(rot.event.k[0])
    const rev = createRevoke(seed, 0, did, rot.event, current, { gen: 0, seq: 1 })
    const result = foldLog(did, [icp, rot, rev])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/key the profile publishes/)
    expect(result.index).toBe(2)
  })

  test('nor one it currently publishes for key agreement', () => {
    const { did, icp, rot } = build()
    const current = keyTarget(rot.event.ka[0])
    const rev = createRevoke(seed, 0, did, rot.event, current, { gen: 0, seq: 1 })
    const result = foldLog(did, [icp, rot, rev])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/key the profile publishes/)
  })

  test('a retired agreement key can be, and the same event at the earlier position cannot', () => {
    // The control for the two rows above: identical event shape, identical signer, and the only
    // difference is whether the named key is still published. Without it, "rejected" could just as
    // well mean the fold refuses every key target outright.
    const { did, icp, rot } = build()
    const retired = keyTarget(icp.event.ka[0])
    const ok = createRevoke(seed, 0, did, rot.event, retired, { gen: 0, seq: 1 })
    expect(foldLog(did, [icp, rot, ok]).ok).toBe(true)

    const tooEarly = createRevoke(seed, 0, did, icp.event, retired, { gen: 0, seq: 0 })
    expect(foldLog(did, [icp, tooEarly]).ok).toBe(false)
  })

  test('a rotate cannot establish a key its own deny snapshot names', () => {
    // `d` is author-written wire data, so a rotate could otherwise publish a key set and deny it in
    // the same event — leaving a head whose `k` resolves to nothing.
    const { did, icp } = build()
    const selfDenying = createRotate(seed, 0, did, icp.event, {
      denySnapshot: [keyTarget(createRotate(seed, 0, did, icp.event).event.k[0])],
    })
    const result = foldLog(did, [icp, selfDenying])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/rotate establishes a denied key/)

    // Control: the same rotate with the same snapshot mechanism, denying a key it does not
    // establish, folds — so the rejection is the collision and not the presence of `d`.
    const other = createRotate(seed, 0, did, icp.event, {
      denySnapshot: [keyTarget(icp.event.k[0])],
    })
    expect(foldLog(did, [icp, other]).ok).toBe(true)
  })

  test('nor one carried forward from a denial made before the key was published', () => {
    // The other route to the same collision, and the one that needs no hand-edited event: the
    // inception *commits* to the next key without publishing it, so a revoke naming that key is
    // accepted — it is in no key set yet — and the rotate that later reveals it walks into an
    // accumulated deny set that already names it. Nothing here is forged; every event is one this
    // package builds and signs.
    const { did, icp, rot } = build()
    const committed = keyTarget(rot.event.k[0])
    const rev = createRevoke(seed, 0, did, icp.event, committed, { gen: 0, seq: 0 })
    const denied = foldLog(did, [icp, rev])
    expect(denied.ok).toBe(true)
    if (!denied.ok) return
    expect(denied.states[1].deny.has(committed)).toBe(true)

    // The rotate reveals exactly the pre-committed key, so it is valid in every other respect.
    const reveal = createRotate(seed, 0, did, rev.event, { keyPosition: { gen: 0, seq: 0 } })
    expect(reveal.event.k).toEqual(rot.event.k)
    const result = foldLog(did, [icp, rev, reveal])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/rotate establishes a denied key/)
    expect(result.index).toBe(2)

    // Control: the identical rotate at the identical position, over a log whose revoke named a
    // device DID instead. Same signer, same commitment, same sequence — so the rejection above is
    // the collision and not the revoke standing between the inception and the rotate.
    const other = createRevoke(seed, 0, did, icp.event, stolen, { gen: 0, seq: 0 })
    const control = createRotate(seed, 0, did, other.event, { keyPosition: { gen: 0, seq: 0 } })
    expect(foldLog(did, [icp, other, control]).ok).toBe(true)
  })
})

describe('keyStateAt()', () => {
  test('returns the state after the event at that position', () => {
    const { did, icp, rot, rev } = build()
    const result = foldLog(did, [icp, rot, rev])
    expect(keyStateAt(result, 1)?.keys).toEqual(rot.event.k)
  })

  test('a device denied later is not denied at an earlier position', () => {
    const { did, icp, rot, rev } = build()
    const result = foldLog(did, [icp, rot, rev])
    expect(keyStateAt(result, 1)?.deny.has(stolen)).toBe(false)
    expect(keyStateAt(result, 2)?.deny.has(stolen)).toBe(true)
  })

  test('a revoke carries the key position forward, so a second revoke can be signed', () => {
    const { did, icp, rot, rev } = build()
    const state = keyStateAt(foldLog(did, [icp, rot, rev]), 2)
    expect(state).toBeDefined()
    if (state == null) return
    // The revoke did not rotate, so the keys are still the rotate's and so is their position.
    expect(state.keys).toEqual(rot.event.k)
    expect(state.keyGen).toBe(0)
    expect(state.keySeq).toBe(1)
    // Signing a second revoke from that position must produce a foldable event — the defect
    // Amendment A fixes was that this chained revoke signed with an unrevealed key.
    const second = createRevoke(seed, 0, did, rev.event, 'did:key:zOther', {
      gen: state.keyGen,
      seq: state.keySeq,
    })
    const chained = foldLog(did, [icp, rot, rev, second])
    expect(chained.ok).toBe(true)
    if (!chained.ok) return
    expect(chained.states[3].deny.has(stolen)).toBe(true)
    expect(chained.states[3].deny.has('did:key:zOther')).toBe(true)
  })

  test('returns undefined past the end of the log', () => {
    const { did, icp } = build()
    expect(keyStateAt(foldLog(did, [icp]), 9)).toBeUndefined()
  })
})
