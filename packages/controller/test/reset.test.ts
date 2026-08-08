import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { createInception, createReset, didFromInception, verifyReset } from '../src/events.js'

const seed = new Uint8Array(32).fill(1)

function setup() {
  const inception = createInception(seed, 0)
  return {
    inception,
    did: didFromInception(inception.event),
    priorDigest: digestOf(inception.event),
  }
}

describe('createReset()', () => {
  test('increments the generation and restarts the sequence', () => {
    const { inception, did } = setup()
    const { event } = createReset(seed, 0, did, inception.event)
    expect(event.g).toBe(1)
    expect(event.s).toBe(0)
  })

  test('is a rotate variant, not a fourth event type', () => {
    const { inception, did } = setup()
    expect(createReset(seed, 0, did, inception.event).event.t).toBe('rot')
  })

  test('clears the deny set by carrying an empty snapshot', () => {
    const { inception, did } = setup()
    expect(createReset(seed, 0, did, inception.event).event.d).toEqual([])
  })
})

describe('verifyReset()', () => {
  test('accepts a reset signed by the committed recovery key', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createReset(seed, 0, did, inception.event)
    expect(verifyReset(signed, { digest: priorDigest, r: inception.event.r })).toBe(true)
  })

  test('rejects a reset signed by any other key — the root always wins the race', () => {
    const { inception, did, priorDigest } = setup()
    const thiefSeed = new Uint8Array(32).fill(9)
    const signed = createReset(thiefSeed, 0, did, inception.event)
    expect(verifyReset(signed, { digest: priorDigest, r: inception.event.r })).toBe(false)
  })

  test('rejects a reset that does not increment the generation', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createReset(seed, 0, did, inception.event)
    const tampered = { ...signed, event: { ...signed.event, g: 0 } }
    expect(verifyReset(tampered, { digest: priorDigest, r: inception.event.r })).toBe(false)
  })
})
