import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  didFromInception,
  type EventCommon,
  type InceptionEvent,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { type FoldResult, foldLog } from '../src/fold.js'

// The rule this file pins: a guard stays when the value it inspects can reach it in the shape it
// rejects, even if no test can kill it, and is removed only when that value cannot reach it at all.
// The block below is the counterpart of a removal: an unkillable guard that stays because the shapes
// it rejects do arrive.

const seed = new Uint8Array(32).fill(77)
const icp = createInception(seed, 0)
const authority = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')

describe('kept: `isKeyList(event.k)` in verifyInception', () => {
  // Unkillable — `verifySignatures` rejects every shape below with the same `invalid inception` —
  // and reachable, which is what decides it. An inception is self-certifying, so each of these is
  // re-signed by the key that legitimately authors it and folded against the DID it hashes to:
  // no signature check can reject them, and only a shape guard says what `k` must be.
  function signedInception(value: unknown): [string, SignedEvent<InceptionEvent>] {
    const event = { ...icp.event, k: value } as unknown as InceptionEvent
    return [
      didFromInception(event),
      { event, sigs: signEvent(event as EventCommon, [authority.privateKey]) },
    ]
  }

  for (const value of [42, 'zNotAnArray', {}, null, [42], [[]], [icp.event.k[0], 42]]) {
    test(`k = ${JSON.stringify(value)} never folds and never throws`, () => {
      const [forgedDid, forged] = signedInception(value)
      let result: FoldResult | undefined
      expect(() => {
        result = foldLog(forgedDid, [forged])
      }).not.toThrow()
      expect(result).toEqual({ ok: false, reason: 'invalid inception', index: 0 })
    })
  }

  test('control: an unmutated re-signed inception folds', () => {
    const [forgedDid, forged] = signedInception(icp.event.k)
    expect(foldLog(forgedDid, [forged]).ok).toBe(true)
  })
})
