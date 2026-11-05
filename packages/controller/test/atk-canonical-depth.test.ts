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
const authorityPrivateKey = deriveKeyPair({
  seed,
  path: authorityPath({ profile: 0, gen: 0, seq: 0 }),
  alg: 'EdDSA',
}).privateKey

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
      const within = withinCanonicalDepth({ value })
      let encoded: string | 'THREW' = 'THREW'
      try {
        encoded = `${canonicalBytes(value).length} bytes`
      } catch {
        /* recorded above */
      }
      expect(within).toBe(encoded !== 'THREW')
    }
  })

  test('ROW 2: a legitimate deeply-nested-but-valid event at exactly 64 still folds', async () => {
    // An inception is self-certifying, so a body carrying an extra deeply-nested member is a valid
    // log for the DID it hashes to. The member nests 63, putting the whole body at 64.
    const base = (await createInception({ seed, profile: 0 })).event
    const event = { ...base, deep: nest(MAX_CANONICAL_DEPTH - 1) } as unknown as InceptionEvent
    const did = didFromInception(event)
    const signed: SignedEvent<InceptionEvent> = {
      event,
      sigs: await signEvent(event, [authorityPrivateKey]),
    }
    const r = await foldLog({ did, input: { chain: [signed], events: [] } })
    expect(r.ok).toBe(true)
  })

  test('ROW 3: the same event one level deeper is REJECTED with a reason, not a throw', async () => {
    const base = (await createInception({ seed, profile: 0 })).event
    const event = { ...base, deep: nest(MAX_CANONICAL_DEPTH) } as unknown as InceptionEvent
    const did = didFromInception(base)
    const signed = { event, sigs: [] } as unknown as SignedEvent
    let thrown: unknown
    let result: unknown
    try {
      result = await foldLog({ did, input: { chain: [signed], events: [] } })
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeUndefined()
    expect(result).toEqual({ ok: false, reason: 'malformed event', index: 0 })
  })

  test('ROW 4: 200k-deep wire input is a returned failure, not a RangeError', async () => {
    const parsed = JSON.parse(`{"event":{"deep":${wireNest(200_000)}},"sigs":[]}`)
    const did = didFromInception((await createInception({ seed, profile: 0 })).event)
    let thrown: unknown
    let result: unknown
    try {
      result = await foldLog({ did, input: { chain: [parsed], events: [] } })
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeUndefined()
    expect(result).toEqual({ ok: false, reason: 'malformed event', index: 0 })
  })

  test('ROW 5: `verifyDigest` answers false rather than throwing on over-deep input', () => {
    const d = digestOf({ a: 1 })
    expect(verifyDigest({ digest: d, value: nest(MAX_CANONICAL_DEPTH + 1) })).toBe(false)
    expect(verifyDigest({ digest: d, value: { a: 1 } })).toBe(true)
  })
})
