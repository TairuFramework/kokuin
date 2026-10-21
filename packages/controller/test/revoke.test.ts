import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  createInception,
  didFromInception,
  KEY_TARGET_PREFIX,
  keyFromTarget,
  keyTarget,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function setup() {
  const inception = createInception(seed, 0)
  return {
    inception,
    did: didFromInception(inception.event),
    priorDigest: digestOf(inception.event),
  }
}

describe('a key target', () => {
  // The spelling is a wire format and the whole of the ambiguity argument rests on it, so it is
  // asserted rather than left to the two call sites that build and read it.
  test('is spelled exactly the way a kid names a key', () => {
    const key = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    expect(keyTarget(key)).toBe(`#${key}`)
    expect(KEY_TARGET_PREFIX).toBe('#')
  })

  test('round-trips, and reads a DID target back as no key at all', () => {
    const key = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    expect(keyFromTarget(keyTarget(key))).toBe(key)
    // The disambiguation that lets one deny set carry both forms: a DID can never read as a key
    // target, so a `did:` entry is never mistaken for a denied key and vice versa.
    expect(keyFromTarget(stolen)).toBeNull()
    expect(keyFromTarget('')).toBeNull()
  })
})

describe('the root chain carries no revoke', () => {
  // A revoke is an epoch event, never a chain event. One on the chain — from an older log, with or
  // without the capability an authorised one carried — is an unknown type, and critical, so the
  // fold fails closed rather than reading it as anything.
  test('a chain revoke, with or without a capability, does not fold', () => {
    const { inception, did, priorDigest } = setup()
    const revoke = { v: 1, t: 'rev', i: did, g: 0, s: 1, p: priorDigest, crit: true, x: stolen }
    for (const event of [revoke, { ...revoke, cap: 'x' }]) {
      const signed = { event, sigs: ['AAAA'] } as unknown as SignedEvent
      expect(foldLog(did, [inception, signed])).toEqual({
        ok: false,
        reason: 'unknown critical event type: rev',
        index: 1,
      })
    }
  })

  test('the chain revoke verifier and the async fold are gone', async () => {
    const controller = await import('../src/index.js')
    expect('verifyRevoke' in controller).toBe(false)
    expect('foldLogAsync' in controller).toBe(false)
    expect('resolveBranchesAsync' in controller).toBe(false)
    expect('createRevokeWithKey' in controller).toBe(false)
  })
})
