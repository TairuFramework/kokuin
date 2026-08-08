import { describe, expect, test } from 'vitest'

import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
} from '../src/events.js'
import { foldLog, keyStateAt } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

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
