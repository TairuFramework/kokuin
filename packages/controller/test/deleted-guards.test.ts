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
const icp = await createInception({ seed, profile: 0 })
const authority = deriveKeyPair({
  seed,
  path: authorityPath({ profile: 0, gen: 0, seq: 0 }),
  alg: 'EdDSA',
})

describe('kept: `isKeyList(event.k)` in verifyInception', () => {
  // Unkillable — `verifySignatures` rejects every shape below with the same `invalid inception` —
  // and reachable, which is what decides it. An inception is self-certifying, so each of these is
  // re-signed by the key that legitimately authors it and folded against the DID it hashes to:
  // no signature check can reject them, and only a shape guard says what `k` must be.
  async function signedInception(value: unknown): Promise<[string, SignedEvent<InceptionEvent>]> {
    const event = { ...icp.event, k: value } as unknown as InceptionEvent
    return [
      didFromInception(event),
      { event, sigs: await signEvent(event as EventCommon, [authority.privateKey]) },
    ]
  }

  for (const value of [42, 'zNotAnArray', {}, null, [42], [[]], [icp.event.k[0], 42]]) {
    test(`k = ${JSON.stringify(value)} never folds and never throws`, async () => {
      const [forgedDID, forged] = await signedInception(value)
      let result: FoldResult | undefined
      await expect(
        (async () => {
          result = await foldLog({ did: forgedDID, input: { chain: [forged], events: [] } })
        })(),
      ).resolves.toBeUndefined()
      expect(result).toEqual({ ok: false, reason: 'invalid inception', index: 0 })
    })
  }

  test('control: an unmutated re-signed inception folds', async () => {
    const [forgedDID, forged] = await signedInception(icp.event.k)
    expect((await foldLog({ did: forgedDID, input: { chain: [forged], events: [] } })).ok).toBe(
      true,
    )
  })
})
