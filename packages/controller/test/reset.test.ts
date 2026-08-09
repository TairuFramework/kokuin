import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  createInception,
  createReset,
  didFromInception,
  signEvent,
  verifyReset,
} from '../src/events.js'

const seed = new Uint8Array(32).fill(1)

function setup() {
  const inception = createInception(seed, 0)
  return {
    inception,
    did: didFromInception(inception.event),
  }
}

describe('createReset()', () => {
  test('increments the generation and restarts the sequence', () => {
    const { event } = createReset(seed, 0, 1)
    expect(event.g).toBe(1)
    expect(event.s).toBe(0)
  })

  test('is a rotate variant, not a fourth event type', () => {
    expect(createReset(seed, 0, 1).event.t).toBe('rot')
  })

  test('clears the deny set by carrying an empty snapshot', () => {
    expect(createReset(seed, 0, 1).event.d).toEqual([])
  })

  test('anchors to the inception, with no reference to any event beyond it', () => {
    const { inception, did } = setup()
    const { event } = createReset(seed, 0, 1)
    expect(event.p).toBe(digestOf(inception.event))
    expect(event.i).toBe(did)
  })

  test('is a pure function of (seed, profile, gen) — two blind resets are byte-identical', () => {
    expect(createReset(seed, 0, 1)).toEqual(createReset(seed, 0, 1))
  })

  test('rejects a generation below 1', () => {
    expect(() => createReset(seed, 0, 0)).toThrow()
  })
})

describe('verifyReset()', () => {
  test('accepts a reset signed by the committed recovery key', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    expect(verifyReset(signed, inception.event)).toBe(true)
  })

  test('rejects a reset signed by any other key — the root always wins the race', () => {
    const { inception } = setup()
    const thiefSeed = new Uint8Array(32).fill(9)
    const signed = createReset(thiefSeed, 0, 1)
    expect(verifyReset(signed, inception.event)).toBe(false)
  })

  test('rejects a reset that does not increment the generation', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    const tampered = { ...signed, event: { ...signed.event, g: 0 } }
    expect(verifyReset(tampered, inception.event)).toBe(false)
  })

  // `p`/`s`/`g` and the revealed recovery key stay exactly as createReset produced them, and the
  // event is re-signed with the real recovery private key over the tampered bytes — so only a
  // dedicated `ka` check, not a chain/recovery/signature failure, can reject these.
  test('rejects a reset publishing no key agreement key', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, ka: [] }
    const sigs = signEvent(event, [recovery.privateKey])
    expect(verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event)).toBe(
      false,
    )
  })

  test('rejects a reset whose ka holds a key that is not X25519-tagged', () => {
    const { inception } = setup()
    const signed = createReset(seed, 0, 1)
    const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')
    const event = { ...signed.event, ka: [signed.event.k[0]] }
    const sigs = signEvent(event, [recovery.privateKey])
    expect(verifyReset({ event, sigs, recoveryKey: signed.recoveryKey }, inception.event)).toBe(
      false,
    )
  })
})
