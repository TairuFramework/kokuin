import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  type RotateEvent,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'
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

describe('pre-rotation bypass attempts', () => {
  const { icp, did } = build(seedA)

  test('a rotate revealing a key that was never committed is refused', () => {
    const honest = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const thief = deriveKeyPair(thiefSeed, authorityPath(0, 0, 1), 'EdDSA')
    const body: RotateEvent = { ...honest.event, k: [encodeKey(thief.publicKey, 'EdDSA')] }
    const forged: SignedEvent<RotateEvent> = {
      event: body,
      sigs: signEvent(body, [thief.privateKey]),
    }
    // The signature is VALID over these bytes and matches the key the event publishes — the only
    // thing wrong is that `n` never committed it.
    expect(foldLog(did, [icp, forged]).ok).toBe(false)
    // CONTROL: the honest rotate, same position, same shape.
    expect(foldLog(did, [icp, honest]).ok).toBe(true)
  })

  test('a rotate re-revealing the CURRENT key (no rotation at all) is refused', () => {
    const honest = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const current = deriveKeyPair(seedA, authorityPath(0, 0, 0), 'EdDSA')
    const body: RotateEvent = { ...honest.event, k: [...icp.event.k] }
    const forged: SignedEvent<RotateEvent> = {
      event: body,
      sigs: signEvent(body, [current.privateKey]),
    }
    expect(foldLog(did, [icp, forged]).ok).toBe(false)
  })

  test('the commitment cannot be satisfied by a differently-encoded spelling of the same key', () => {
    // `n` commits `digestOf(<the multibase string>)`, so the encoding is part of the commitment.
    const honest = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const spelled = honest.event.k[0]
    if (spelled === undefined) throw new Error('expected a rotated key')
    expect(digestOf(spelled)).toBe(icp.event.n[0])
    expect(digestOf(spelled.toUpperCase())).not.toBe(icp.event.n[0])
  })

  test('a rotate padding `k`/`n` to smuggle an extra key in is refused', () => {
    const honest = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const thief = deriveKeyPair(thiefSeed, authorityPath(0, 0, 0), 'EdDSA')
    const thiefKey = encodeKey(thief.publicKey, 'EdDSA')
    const body: RotateEvent = { ...honest.event, k: [...honest.event.k, thiefKey] }
    const revealed = deriveKeyPair(seedA, authorityPath(0, 0, 1), 'EdDSA')
    const forged: SignedEvent<RotateEvent> = {
      event: body,
      sigs: signEvent(body, [revealed.privateKey, thief.privateKey]),
    }
    expect(foldLog(did, [icp, forged]).ok).toBe(false)
  })
})

describe('splicing, truncation, replay', () => {
  test("an event from another DID's log is refused by the `i` check", () => {
    const a = build(seedA)
    const b = build(seedB)
    const foreignRotate = createRotate({
      seed: seedB,
      profile: 0,
      did: b.did,
      prior: b.icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    expect(foldLog(a.did, [a.icp, foreignRotate]).ok).toBe(false)
  })

  test("another DID's reset, relabelled with our `i`, is refused (anchor + recovery)", () => {
    const a = build(seedA)
    const foreignReset = createReset(seedB, 0, 1)
    const relabelled: SignedEvent<RotateEvent> = {
      ...foreignReset,
      event: { ...foreignReset.event, i: a.did, p: digestOf(a.icp.event) },
    }
    expect(foldLog(a.did, [a.icp, relabelled]).ok).toBe(false)
  })

  test('a rotate replayed at a later position is refused', () => {
    const { icp, did } = build(seedA)
    const rot1 = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const rot2 = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: rot1.event,
      options: { snapshot: { members: [], deny: [victim] } },
    })
    expect(foldLog(did, [icp, rot1, rot2]).ok).toBe(true)
    expect(foldLog(did, [icp, rot1, rot1]).ok).toBe(false)
    expect(foldLog(did, [icp, rot2]).ok).toBe(false)
  })

  test('reordering two valid events is refused', () => {
    const { icp, did } = build(seedA)
    const rot = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const next = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: rot.event,
      options: { snapshot: { members: [], deny: [victim] } },
    })
    expect(foldLog(did, [icp, rot, next]).ok).toBe(true)
    expect(foldLog(did, [icp, next, rot]).ok).toBe(false)
  })

  test('a prefix truncation folds (by design) but loses branch selection on (gen, seq)', () => {
    const { icp, did } = build(seedA)
    const rot = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const denying = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: rot.event,
      options: { snapshot: { members: [], deny: [victim] } },
    })
    const honest = [icp, rot, denying]
    expect(foldLog(did, [icp]).ok).toBe(true)
    const r = resolveBranches(did, [[icp], honest])
    expect(r.ok && r.winner).toBe(honest)
  })
})

describe('superseding recovery abuse', () => {
  test('a stolen CURRENT key extends the root chain with nothing, so the owner rotate wins outright', () => {
    const { icp, did } = build(seedA)
    // The chain holds only `icp`/`rot`, and a rotate must reveal the pre-committed key: the only
    // other thing a current-key holder can sign is an event of a type the chain does not carry.
    const current = deriveKeyPair(seedA, authorityPath(0, 0, 0), 'EdDSA')
    const revokeBody = {
      v: 1,
      t: 'rev',
      i: did,
      g: 0,
      s: 1,
      p: digestOf(icp.event),
      crit: true,
      x: victim,
    }
    const thiefRevoke = {
      event: revokeBody,
      sigs: signEvent(revokeBody as never, [current.privateKey]),
    } as unknown as SignedEvent
    expect(foldLog(did, [icp, thiefRevoke]).ok).toBe(false)
    const ownerRotate = createRotate({
      seed: seedA,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    for (const order of [
      [
        [icp, thiefRevoke],
        [icp, ownerRotate],
      ],
      [
        [icp, ownerRotate],
        [icp, thiefRevoke],
      ],
    ]) {
      const r = resolveBranches(did, order)
      expect(r.ok && r.winner[1]).toBe(ownerRotate)
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
    expect(r.ok && r.winner[1]?.event.g).toBe(2)
    // And replaying the lower reset after the higher one does not fold.
    expect(foldLog(did, [icp, reset2, reset1]).ok).toBe(false)
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
    expect(foldLog(did, [icp, forged]).ok).toBe(false)
    // CONTROL: identical body, the real recovery key.
    expect(foldLog(did, [icp, honest]).ok).toBe(true)
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
    expect(foldLog(did, [icp, forged]).ok).toBe(false)
  })
})

describe('self-certification', () => {
  test('a log whose inception is not the one the DID hashes is refused', () => {
    const a = build(seedA)
    const b = build(seedB)
    expect(foldLog(a.did, [b.icp]).ok).toBe(false)
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
      expect(seen.has(d)).toBe(false)
      seen.add(d)
    }
  })

  test('an undefined-valued member is dropped, so it names the same DID (no wire difference)', () => {
    const { icp } = build(seedA)
    const withUndefined = { ...icp.event, extra: undefined } as never
    expect(didFromInception(withUndefined)).toBe(didFromInception(icp.event))
  })

  test('`__proto__` off the wire is covered by the digest and pollutes nothing', () => {
    const parsed = JSON.parse('{"a":1,"__proto__":{"polluted":true}}')
    expect(digestOf(parsed)).not.toBe(digestOf({ a: 1 }))
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
  })

  test('unicode: distinct strings never share a canonical form', () => {
    const composed = 'é'
    const precomposed = 'é'
    expect(digestOf(composed)).not.toBe(digestOf(precomposed))
    expect(digestOf({ b: 1, a: 2 })).toBe(digestOf({ a: 2, b: 1 }))
  })
})
