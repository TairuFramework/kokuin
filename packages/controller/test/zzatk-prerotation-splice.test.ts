import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  encodeKey,
  type RotateEvent,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

const seedA = new Uint8Array(32).fill(1)
const seedB = new Uint8Array(32).fill(2)
const thiefSeed = new Uint8Array(32).fill(66)
const victim = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build(seed: Uint8Array) {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  return { icp, did }
}

function report(label: string, r: ReturnType<typeof foldLog>) {
  console.log(`${label}:`, r.ok ? 'ACCEPTED' : `rejected — ${r.reason} @${r.index}`)
  return r
}

describe('pre-rotation bypass attempts', () => {
  const { icp, did } = build(seedA)

  test('a rotate revealing a key that was never committed is refused', () => {
    const honest = createRotate(seedA, 0, did, icp.event)
    const thief = deriveKeyPair(thiefSeed, authorityPath(0, 0, 1), 'EdDSA')
    const body: RotateEvent = { ...honest.event, k: [encodeKey(thief.publicKey, 'EdDSA')] }
    const forged: SignedEvent<RotateEvent> = {
      event: body,
      sigs: signEvent(body, [thief.privateKey]),
    }
    // The signature is VALID over these bytes and matches the key the event publishes — the only
    // thing wrong is that `n` never committed it.
    console.log('signature is self-consistent:', forged.sigs.length === body.k.length)
    expect(report('rotate with an uncommitted key', foldLog(did, [icp, forged])).ok).toBe(false)
    // CONTROL: the honest rotate, same position, same shape.
    expect(report('CONTROL honest rotate', foldLog(did, [icp, honest])).ok).toBe(true)
  })

  test('a rotate re-revealing the CURRENT key (no rotation at all) is refused', () => {
    const honest = createRotate(seedA, 0, did, icp.event)
    const current = deriveKeyPair(seedA, authorityPath(0, 0, 0), 'EdDSA')
    const body: RotateEvent = { ...honest.event, k: [...icp.event.k] }
    const forged: SignedEvent<RotateEvent> = {
      event: body,
      sigs: signEvent(body, [current.privateKey]),
    }
    expect(report('rotate re-revealing the current key', foldLog(did, [icp, forged])).ok).toBe(
      false,
    )
  })

  test('the commitment cannot be satisfied by a differently-encoded spelling of the same key', () => {
    // `n` commits `digestOf(<the multibase string>)`, so the encoding is part of the commitment.
    const honest = createRotate(seedA, 0, did, icp.event)
    const spelled = honest.event.k[0]
    console.log('committed digest:', icp.event.n[0])
    console.log('digestOf(revealed string):', digestOf(spelled))
    console.log('digestOf(the same string uppercased):', digestOf(spelled.toUpperCase()))
    expect(digestOf(spelled)).toBe(icp.event.n[0])
    expect(digestOf(spelled.toUpperCase())).not.toBe(icp.event.n[0])
  })

  test('a rotate padding `k`/`n` to smuggle an extra key in is refused', () => {
    const honest = createRotate(seedA, 0, did, icp.event)
    const thief = deriveKeyPair(thiefSeed, authorityPath(0, 0, 0), 'EdDSA')
    const thiefKey = encodeKey(thief.publicKey, 'EdDSA')
    const body: RotateEvent = { ...honest.event, k: [...honest.event.k, thiefKey] }
    const revealed = deriveKeyPair(seedA, authorityPath(0, 0, 1), 'EdDSA')
    const forged: SignedEvent<RotateEvent> = {
      event: body,
      sigs: signEvent(body, [revealed.privateKey, thief.privateKey]),
    }
    expect(report('rotate with an appended key', foldLog(did, [icp, forged])).ok).toBe(false)
  })
})

describe('splicing, truncation, replay', () => {
  test("an event from another DID's log is refused by the `i` check", () => {
    const a = build(seedA)
    const b = build(seedB)
    const foreignRotate = createRotate(seedB, 0, b.did, b.icp.event)
    expect(report('foreign rotate spliced in', foldLog(a.did, [a.icp, foreignRotate])).ok).toBe(
      false,
    )
  })

  test("another DID's reset, relabelled with our `i`, is refused (anchor + recovery)", () => {
    const a = build(seedA)
    const b = build(seedB)
    const foreignReset = createReset(seedB, 0, 1)
    const relabelled: SignedEvent<RotateEvent> = {
      ...foreignReset,
      event: { ...foreignReset.event, i: a.did, p: digestOf(a.icp.event) },
    }
    expect(report('foreign reset relabelled', foldLog(a.did, [a.icp, relabelled])).ok).toBe(false)
  })

  test('a rotate replayed at a later position is refused', () => {
    const { icp, did } = build(seedA)
    const rot1 = createRotate(seedA, 0, did, icp.event)
    const rot2 = createRotate(seedA, 0, did, rot1.event, { keyPosition: { gen: 0, seq: 1 } })
    expect(report('valid two-rotate log', foldLog(did, [icp, rot1, rot2])).ok).toBe(true)
    expect(report('rot1 replayed at position 2', foldLog(did, [icp, rot1, rot1])).ok).toBe(false)
    expect(report('rot2 hoisted to position 1', foldLog(did, [icp, rot2])).ok).toBe(false)
  })

  test('a revoke replayed at a later position is refused', () => {
    const { icp, did } = build(seedA)
    const rev = createRevoke(seedA, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    expect(report('valid revoke', foldLog(did, [icp, rev])).ok).toBe(true)
    expect(report('revoke replayed', foldLog(did, [icp, rev, rev])).ok).toBe(false)
  })

  test('reordering two valid events is refused', () => {
    const { icp, did } = build(seedA)
    const rot = createRotate(seedA, 0, did, icp.event)
    const rev = createRevoke(seedA, 0, did, rot.event, victim, { gen: 0, seq: 1 })
    expect(report('correct order', foldLog(did, [icp, rot, rev])).ok).toBe(true)
    expect(report('swapped order', foldLog(did, [icp, rev, rot])).ok).toBe(false)
  })

  test('a prefix truncation folds (by design) but loses branch selection on (gen, seq)', () => {
    const { icp, did } = build(seedA)
    const rot = createRotate(seedA, 0, did, icp.event)
    const rev = createRevoke(seedA, 0, did, rot.event, victim, { gen: 0, seq: 1 })
    const honest = [icp, rot, rev]
    expect(report('truncated to the inception', foldLog(did, [icp])).ok).toBe(true)
    const r = resolveBranches(did, [[icp], honest])
    console.log('winner length with a truncated rival:', r.ok ? r.winner.length : 'duplicity')
    expect(r.ok && r.winner).toBe(honest)
  })
})

describe('superseding recovery abuse', () => {
  test('a stolen CURRENT key cannot outrank the owner rotate at the same position', () => {
    const { icp, did } = build(seedA)
    const thiefRevoke = createRevoke(seedA, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    const ownerRotate = createRotate(seedA, 0, did, icp.event)
    const r = resolveBranches(did, [
      [icp, thiefRevoke],
      [icp, ownerRotate],
    ])
    console.log('winner head type:', r.ok ? r.winner[1].event.t : 'duplicity')
    expect(r.ok && r.winner[1].event.t).toBe('rot')
  })

  test('a revoke can never supersede a rotate, in either presentation order', () => {
    const { icp, did } = build(seedA)
    const rev = createRevoke(seedA, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    const rot = createRotate(seedA, 0, did, icp.event)
    for (const order of [
      [
        [icp, rev],
        [icp, rot],
      ],
      [
        [icp, rot],
        [icp, rev],
      ],
    ]) {
      const r = resolveBranches(did, order)
      console.log('order-independent winner:', r.ok ? r.winner[1].event.t : 'duplicity')
      expect(r.ok && r.winner[1].event.t).toBe('rot')
    }
  })

  test('a reset cannot resurrect an older generation: a lower `g` never outranks a higher one', () => {
    const { icp, did } = build(seedA)
    const reset1 = createReset(seedA, 0, 1)
    const reset2 = createReset(seedA, 0, 2)
    const r = resolveBranches(did, [
      [icp, reset2],
      [icp, reset1],
    ])
    console.log('winner generation:', r.ok ? r.winner[1].event.g : 'duplicity')
    expect(r.ok && r.winner[1].event.g).toBe(2)
    // And replaying the lower reset after the higher one does not fold.
    expect(report('reset(1) appended after reset(2)', foldLog(did, [icp, reset2, reset1])).ok).toBe(
      false,
    )
  })

  test('a reset a non-root forges is refused — the recovery key is unpublished', () => {
    const { icp, did } = build(seedA)
    const honest = createReset(seedA, 0, 1)
    const thief = deriveKeyPair(thiefSeed, authorityPath(0, 0, 0), 'EdDSA')
    const forged: SignedEvent<RotateEvent> = {
      event: honest.event,
      sigs: signEvent(honest.event, [thief.privateKey]),
      recoveryKey: encodeKey(thief.publicKey, 'EdDSA'),
    }
    expect(report('reset signed by a stranger', foldLog(did, [icp, forged])).ok).toBe(false)
    // CONTROL: identical body, the real recovery key.
    expect(report('CONTROL real reset', foldLog(did, [icp, honest])).ok).toBe(true)
  })

  test('a reset revealing the right recovery key but a forged signature is refused', () => {
    const { icp, did } = build(seedA)
    const honest = createReset(seedA, 0, 1)
    const thief = deriveKeyPair(thiefSeed, authorityPath(0, 0, 0), 'EdDSA')
    // The revealed key matches `inception.r`; only the signature is somebody else's.
    const forged: SignedEvent<RotateEvent> = {
      event: honest.event,
      sigs: signEvent(honest.event, [thief.privateKey]),
      recoveryKey: honest.recoveryKey,
    }
    console.log(
      'revealed key matches the commitment:',
      digestOf(forged.recoveryKey) === icp.event.r,
    )
    expect(report('reset with a foreign signature', foldLog(did, [icp, forged])).ok).toBe(false)
  })
})

describe('self-certification', () => {
  test('a log whose inception is not the one the DID hashes is refused', () => {
    const a = build(seedA)
    const b = build(seedB)
    expect(report("B's inception under A's DID", foldLog(a.did, [b.icp])).ok).toBe(false)
    console.log('DIDs differ:', a.did !== b.did)
  })

  test('mutating any inception member changes the DID, so no two bodies share one', () => {
    const { icp } = build(seedA)
    const variants: Array<[string, unknown]> = [
      ['g', 1],
      ['s', 1],
      ['kt', 2],
      ['nt', 2],
      ['crit', false],
      ['v', 2],
    ]
    const seen = new Set([didFromInception(icp.event)])
    for (const [field, value] of variants) {
      const d = didFromInception({ ...icp.event, [field]: value })
      console.log(`mutating ${field} ->`, d.slice(0, 24), seen.has(d) ? 'COLLISION' : 'distinct')
      expect(seen.has(d)).toBe(false)
      seen.add(d)
    }
  })

  test('an undefined-valued member is dropped, so it names the same DID (no wire difference)', () => {
    const { icp } = build(seedA)
    const withUndefined = { ...icp.event, extra: undefined } as never
    console.log('same DID:', didFromInception(withUndefined) === didFromInception(icp.event))
    console.log(
      'JSON wire forms identical:',
      JSON.stringify(withUndefined) === JSON.stringify(icp.event),
    )
    expect(didFromInception(withUndefined)).toBe(didFromInception(icp.event))
  })

  test('`__proto__` off the wire is covered by the digest and pollutes nothing', () => {
    const parsed = JSON.parse('{"a":1,"__proto__":{"polluted":true}}')
    console.log('digest with __proto__:', digestOf(parsed).slice(0, 20))
    console.log('digest without:', digestOf({ a: 1 }).slice(0, 20))
    console.log('Object.prototype polluted:', ({} as Record<string, unknown>).polluted)
    expect(digestOf(parsed)).not.toBe(digestOf({ a: 1 }))
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
  })

  test('unicode: distinct strings never share a canonical form', () => {
    const composed = 'é'
    const precomposed = 'é'
    console.log('NFC-distinct strings collide:', digestOf(composed) === digestOf(precomposed))
    console.log('key order is normalised:', digestOf({ b: 1, a: 2 }) === digestOf({ a: 2, b: 1 }))
    expect(digestOf(composed)).not.toBe(digestOf(precomposed))
    expect(digestOf({ b: 1, a: 2 })).toBe(digestOf({ a: 2, b: 1 }))
  })
})
