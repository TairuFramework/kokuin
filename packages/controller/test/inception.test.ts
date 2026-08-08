import { describe, expect, test } from 'vitest'

import { createInception, didFromInception, verifyInception } from '../src/events.js'

const seedA = new Uint8Array(32).fill(1)
const seedB = new Uint8Array(32).fill(2)

describe('createInception()', () => {
  test('is a pure function of seed and profile index', () => {
    expect(createInception(seedA, 0)).toEqual(createInception(seedA, 0))
  })

  test('contains no timestamp, nonce or label', () => {
    const { event } = createInception(seedA, 0)
    const keys = Object.keys(event).sort()
    expect(keys).toEqual(['crit', 'g', 'k', 'kt', 'n', 'nt', 'r', 's', 't', 'v'])
  })

  test('omits `i` from the inception body — the DID is its hash', () => {
    expect(createInception(seedA, 0).event.i).toBeUndefined()
  })

  test('starts at generation 0, sequence 0', () => {
    const { event } = createInception(seedA, 0)
    expect(event.g).toBe(0)
    expect(event.s).toBe(0)
  })

  test('has no previous-event digest', () => {
    expect(createInception(seedA, 0).event.p).toBeUndefined()
  })

  test('commits next-key digests, not next keys', () => {
    const { event } = createInception(seedA, 0)
    expect(event.n).toHaveLength(1)
    expect(event.n[0]).not.toBe(event.k[0])
  })

  test('commits a recovery key digest', () => {
    expect(createInception(seedA, 0).event.r).toMatch(/^z/)
  })

  test('is marked critical — a verifier that cannot read it must not proceed', () => {
    expect(createInception(seedA, 0).event.crit).toBe(true)
  })
})

describe('didFromInception()', () => {
  test('regenerates the same DID from the same mnemonic and index', () => {
    expect(didFromInception(createInception(seedA, 0).event)).toBe(
      didFromInception(createInception(seedA, 0).event),
    )
  })

  test('differs per profile index, so profiles are enumerable and distinct', () => {
    expect(didFromInception(createInception(seedA, 0).event)).not.toBe(
      didFromInception(createInception(seedA, 1).event),
    )
  })

  test('differs per seed', () => {
    expect(didFromInception(createInception(seedA, 0).event)).not.toBe(
      didFromInception(createInception(seedB, 0).event),
    )
  })

  test('carries no version segment', () => {
    const did = didFromInception(createInception(seedA, 0).event)
    expect(did).toMatch(/^did:kokuin:z[1-9A-HJ-NP-Za-km-z]+$/)
    expect(did.split(':')).toHaveLength(3)
  })
})

describe('verifyInception()', () => {
  test('accepts a self-consistent inception', () => {
    const signed = createInception(seedA, 0)
    expect(verifyInception(signed, didFromInception(signed.event))).toBe(true)
  })

  test('rejects a DID that is not the hash of the event', () => {
    const signed = createInception(seedA, 0)
    const other = didFromInception(createInception(seedA, 1).event)
    expect(verifyInception(signed, other)).toBe(false)
  })

  test('rejects a tampered key set', () => {
    const signed = createInception(seedA, 0)
    const did = didFromInception(signed.event)
    const tampered = { ...signed, event: { ...signed.event, k: ['zBOGUS'] } }
    expect(verifyInception(tampered, did)).toBe(false)
  })

  test('rejects a bad signature', () => {
    const signed = createInception(seedA, 0)
    const did = didFromInception(signed.event)
    expect(verifyInception({ ...signed, sigs: ['zzz'] }, did)).toBe(false)
  })
})
