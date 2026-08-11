import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRevoke,
  didFromInception,
  type EventCommon,
  type InceptionEvent,
  type RevokeEvent,
  type SignedEvent,
  signEvent,
  verifyEventSignedBy,
} from '../src/events.js'
import { type FoldResult, foldLog, foldLogAsync } from '../src/fold.js'

// The rule this file pins, stated at `verifyEventSignedBy`: a guard stays when the value it
// inspects can reach it in the shape it rejects, even if no test can kill it, and is removed only
// when that value cannot reach it at all. Removal therefore owes a proof of unreachability, which
// is what the first block is; the second block is the counterpart, an unkillable guard that stays
// because the shapes it rejects do arrive.

const seed = new Uint8Array(32).fill(77)
const icp = createInception(seed, 0)
const did = didFromInception(icp.event)
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const authority = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
const capRevoke = createRevoke(seed, 0, did, icp.event, target, { gen: 0, seq: 0 }, { cap: 'CAP' })

/**
 * A verifier that authorises everything, pinning the profile's own key — the maximally permissive
 * answer, so nothing short of the envelope guard can stop the fold reaching `verifyEventSignedBy`.
 */
const permissive = async () => ({
  authorised: true as const,
  audienceKey: { alg: 'EdDSA' as const, publicKey: authority.publicKey },
})

describe('removed: `Array.isArray(signed.sigs)` in verifyEventSignedBy', () => {
  test('it is not part of the package surface', async () => {
    const barrel = await import('../src/index.js')
    expect('verifyEventSignedBy' in barrel).toBe(false)
  })

  for (const sigs of [undefined, null, 'z', 42, {}, { length: 1, 0: 'z' }, true]) {
    test(`a cap-revoke whose sigs is ${JSON.stringify(sigs) ?? 'undefined'} never reaches it`, async () => {
      const evil = { ...capRevoke, sigs } as unknown as SignedEvent
      let result: unknown
      await expect(
        (async () => {
          result = await foldLogAsync(did, [icp, evil], { verifyCapability: permissive })
        })(),
      ).resolves.toBeUndefined()
      // Stopped by the envelope guard, before any body verifier — so the removed check's site is
      // unreachable for every non-array `sigs`.
      expect(result).toEqual({ ok: false, reason: 'malformed event', index: 1 })
    })
  }

  test('control: an array `sigs` does reach it, and the audience binding fires', async () => {
    // Signed by a key that is *not* the pinned one, so reaching the site is observable.
    const stranger = deriveKeyPair(new Uint8Array(32).fill(78), authorityPath(0, 0, 0), 'EdDSA')
    const event = capRevoke.event as RevokeEvent
    const signed: SignedEvent<RevokeEvent> = {
      event,
      sigs: signEvent(event, [stranger.privateKey]),
    }
    await expect(
      foldLogAsync(did, [icp, signed], { verifyCapability: permissive }),
    ).resolves.toEqual({
      ok: false,
      reason: 'revoke is not signed by the capability audience',
      index: 1,
    })
  })

  test('called directly with a non-array `sigs`, it does throw — but nothing can call it', () => {
    expect(() =>
      verifyEventSignedBy({ event: capRevoke.event, sigs: 'z' } as unknown as SignedEvent, {
        alg: 'EdDSA',
        publicKey: authority.publicKey,
      }),
    ).toThrow(TypeError)
  })
})

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
