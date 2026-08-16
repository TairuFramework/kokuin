import { describe, expect, test } from 'vitest'

import {
  canonicalBytes,
  digestOf,
  MAX_CANONICAL_DEPTH,
  verifyDigest,
  withinCanonicalDepth,
} from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  didFromInception,
  type InceptionEvent,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const authorityPrivateKey = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').privateKey

/** A value whose total nesting depth (counting the top level as 1) is `depth`. */
function nest(depth: number): unknown {
  let value: unknown = 0
  for (let i = 1; i < depth; i++) {
    value = [value]
  }
  return value
}

function wireNest(depth: number): string {
  return `${'['.repeat(depth - 1)}0${']'.repeat(depth - 1)}`
}

describe('MAX_CANONICAL_DEPTH: both directions', () => {
  test('ROW 1: the two implementations agree exactly on the boundary', () => {
    const depths = [1, 2, 3, MAX_CANONICAL_DEPTH - 1, MAX_CANONICAL_DEPTH, MAX_CANONICAL_DEPTH + 1]
    for (const depth of depths) {
      const value = nest(depth)
      const within = withinCanonicalDepth(value)
      let encoded: string | 'THREW' = 'THREW'
      try {
        encoded = `${canonicalBytes(value).length} bytes`
      } catch {
        /* recorded above */
      }
      expect(within).toBe(encoded !== 'THREW')
    }
  })

  test('ROW 2: a legitimate deeply-nested-but-valid event at exactly 64 still folds', () => {
    // An inception is self-certifying, so a body carrying an extra deeply-nested member is a valid
    // log for the DID it hashes to. The member nests 63, putting the whole body at 64.
    const base = createInception(seed, 0).event
    const event = { ...base, deep: nest(MAX_CANONICAL_DEPTH - 1) } as unknown as InceptionEvent
    const did = didFromInception(event)
    const signed: SignedEvent<InceptionEvent> = {
      event,
      sigs: signEvent(event, [authorityPrivateKey]),
    }
    const r = foldLog(did, [signed])
    expect(r.ok).toBe(true)
  })

  test('ROW 3: the same event one level deeper is REJECTED with a reason, not a throw', () => {
    const base = createInception(seed, 0).event
    const event = { ...base, deep: nest(MAX_CANONICAL_DEPTH) } as unknown as InceptionEvent
    const did = didFromInception(base)
    const signed = { event, sigs: [] } as unknown as SignedEvent
    let thrown: unknown
    let result: unknown
    try {
      result = foldLog(did, [signed])
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeUndefined()
    expect(result).toEqual({ ok: false, reason: 'malformed event', index: 0 })
  })

  test('ROW 4: 200k-deep wire input is a returned failure, not a RangeError', () => {
    const parsed = JSON.parse(`{"event":{"deep":${wireNest(200_000)}},"sigs":[]}`)
    const did = didFromInception(createInception(seed, 0).event)
    let thrown: unknown
    let result: unknown
    try {
      result = foldLog(did, [parsed])
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeUndefined()
    expect(result).toEqual({ ok: false, reason: 'malformed event', index: 0 })
  })

  test('ROW 5: `verifyDigest` answers false rather than throwing on over-deep input', () => {
    const d = digestOf({ a: 1 })
    expect(verifyDigest(d, nest(MAX_CANONICAL_DEPTH + 1))).toBe(false)
    expect(verifyDigest(d, { a: 1 })).toBe(true)
  })
})
