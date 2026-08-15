import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  didFromInception,
  encodeKey,
  type InceptionEvent,
  signEvent,
  verifyInception,
} from '../src/events.js'

const seedA = new Uint8Array(32).fill(1)
const seedB = new Uint8Array(32).fill(2)

describe('createInception()', () => {
  test('is a pure function of seed and profile index', () => {
    expect(createInception(seedA, 0)).toEqual(createInception(seedA, 0))
  })

  test('contains no timestamp, nonce or label', () => {
    const { event } = createInception(seedA, 0)
    const keys = Object.keys(event).sort()
    expect(keys).toEqual(['crit', 'g', 'k', 'ka', 'kt', 'n', 'nt', 'r', 's', 't', 'v'])
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

  test('carries exactly one key agreement key, encoded and tagged like the authority key', () => {
    const { event } = createInception(seedA, 0)
    expect(event.ka).toHaveLength(1)
    expect(event.ka[0]).toMatch(/^z/)
    expect(event.ka[0]).not.toBe(event.k[0])
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

  // Each case below rebuilds the inception event with one field tampered, then re-signs the
  // tampered event with the real authority key and recomputes the DID from it. That makes the DID
  // check and the signature check pass on the tampered event itself, so the only thing left that
  // can reject is the guard under test — a naive tamper-and-reuse-the-old-signature-and-DID test
  // would fail at the DID check (events.ts, the `didFromInception(signed.event) !== did` line)
  // before ever reaching these guards, certifying nothing about them.
  function resign(event: InceptionEvent) {
    const current = deriveKeyPair(seedA, authorityPath(0, 0, 0), 'EdDSA')
    return {
      event,
      sigs: signEvent(event, [current.privateKey]),
      did: didFromInception(event),
    }
  }

  test('rejects an inception publishing no key agreement key', () => {
    const { event } = createInception(seedA, 0)
    const { did, ...tampered } = resign({ ...event, ka: [] })
    expect(verifyInception(tampered, did)).toBe(false)
  })

  test('rejects an inception whose ka holds a key that is not X25519-tagged', () => {
    const { event } = createInception(seedA, 0)
    // A genuine, correctly-sized key, tagged as the wrong algorithm.
    const { did, ...tampered } = resign({ ...event, ka: [event.k[0]] })
    expect(verifyInception(tampered, did)).toBe(false)
  })

  test('rejects an inception whose ka holds an untagged or malformed value', () => {
    const { event } = createInception(seedA, 0)
    const { did, ...tampered } = resign({ ...event, ka: ['zBOGUS'] })
    expect(verifyInception(tampered, did)).toBe(false)
  })

  test('rejects an inception whose k holds an X25519-tagged key rather than EdDSA', () => {
    const { event } = createInception(seedA, 0)
    const current = deriveKeyPair(seedA, authorityPath(0, 0, 0), 'EdDSA')
    // The real authority key, mistagged as key agreement rather than substituted for a different
    // key — a genuine signature by this exact key over these exact bytes verifies cleanly, so this
    // only fails if verification checks the tag, not just the signature.
    const { did, ...tampered } = resign({ ...event, k: [encodeKey(current.publicKey, 'X25519')] })
    expect(verifyInception(tampered, did)).toBe(false)
  })
})

describe('the published thresholds mean what the fold enforces', () => {
  // `kt` and `nt` were published, digested into the event — and therefore into the DID — declared
  // in the type with real semantics, and read by nothing. The fold enforces n-of-n and only n-of-n:
  // `verifySignatures` wants one valid signature per published key, and `verifyRotate` wants every
  // committed key revealed and signing. So the only threshold these can truthfully carry is the
  // size of the set they govern, and anything else is an event whose own declaration contradicts
  // the rule it will be judged by. Inside a wire format the DID derivation freezes, a field nothing
  // reads is a trap for the next reader.
  function inceptionWith(patch: Record<string, unknown>) {
    const base = createInception(seedA, 0)
    const event = { ...base.event, ...patch } as unknown as InceptionEvent
    const current = deriveKeyPair(seedA, authorityPath(0, 0, 0), 'EdDSA')
    const signed = { event, sigs: signEvent(event, [current.privateKey]) }
    return { signed, did: didFromInception(event) }
  }

  test('the generator publishes the enforced thresholds', () => {
    const { event } = createInception(seedA, 0)
    expect(event.kt).toBe(event.k.length)
    expect(event.nt).toBe(event.n.length)
  })

  for (const kt of [0, 2, 99, -1, '1', null, undefined, true]) {
    test(`an inception declaring kt=${JSON.stringify(kt)} over one key is rejected`, () => {
      const { signed, did } = inceptionWith({ kt })
      expect(verifyInception(signed, did)).toBe(false)
    })
  }

  for (const nt of [0, 2, 99, '1', null, undefined]) {
    test(`an inception declaring nt=${JSON.stringify(nt)} over one commitment is rejected`, () => {
      const { signed, did } = inceptionWith({ nt })
      expect(verifyInception(signed, did)).toBe(false)
    })
  }

  test('control: the same re-signing path with truthful thresholds verifies', () => {
    // Every rejection above is the threshold and not the rebuild — the body goes through the same
    // spread, the same signature and the same DID derivation.
    const { signed, did } = inceptionWith({ kt: 1, nt: 1 })
    expect(verifyInception(signed, did)).toBe(true)
  })
})
