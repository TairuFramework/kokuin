import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  encodeKey,
} from '../src/events.js'
import { createControllerIdentity, createControllerIdentityAsync } from '../src/identity.js'

const seed = new Uint8Array(32).fill(7)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
// Not the controller's seed: the revoke below is signed by a delegate, so only the capability it
// carries can authorise it.
const delegateSeed = new Uint8Array(32).fill(3)
const cap = 'eyJ.delegated.revoke'

function authorityKey(gen: number, seq: number): string {
  return encodeKey(deriveKeyPair(seed, authorityPath(0, gen, seq), 'EdDSA').publicKey, 'EdDSA')
}

/** A log whose last event is a capability-authorised revoke — foldable only asynchronously. */
function capLog() {
  const inception = createInception(seed, 0)
  const did = didFromInception(inception.event)
  const revoke = createRevoke(
    delegateSeed,
    0,
    did,
    inception.event,
    device,
    { gen: 0, seq: 0 },
    { cap },
  )
  return { did, log: [inception, revoke], inception }
}

describe('createControllerIdentity()', () => {
  test('binds the identity to the did:kokuin: DID, not a did:key:', async () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const identity = createControllerIdentity(seed, 0, [inception])

    expect(identity.id).toBe(did)

    const signed = await identity.signToken({ hello: 'world' })
    expect(signed.payload.iss).toBe(did)
  })

  test('keeps the payload issuer guard', async () => {
    const identity = createControllerIdentity(seed, 0, [createInception(seed, 0)])
    await expect(
      identity.signToken({ iss: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' }),
    ).rejects.toThrow(/issuer does not match signer/)
  })

  test('signs with the rotated key after a rotation, not the inception key', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate(seed, 0, did, inception.event)

    const identity = createControllerIdentity(seed, 0, [inception, rotate])
    const publicKey = encodeKey(identity.publicKey, 'EdDSA')

    // The key the rotate published, which is the only one the resolver will answer with.
    expect(publicKey).toBe(rotate.event.k[0])
    expect(publicKey).toBe(authorityKey(0, 1))
    // The inception key is retired: signing with it after a rotation is the failure a rotation
    // exists to prevent.
    expect(publicKey).not.toBe(inception.event.k[0])
    expect(publicKey).not.toBe(authorityKey(0, 0))
  })

  test('signs at the key position, not the event position, after a revoke', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    // A revoke advances `seq` to 1 but establishes no key — Amendment A. The active authority key
    // is still the inception's, at gen 0 / seq 0.
    const revoke = createRevoke(seed, 0, did, inception.event, device, { gen: 0, seq: 0 })

    const identity = createControllerIdentity(seed, 0, [inception, revoke])
    const publicKey = encodeKey(identity.publicKey, 'EdDSA')

    expect(publicKey).toBe(inception.event.k[0])
    // Deriving at `gen`/`seq` would land on (0, 1) — the pre-committed *next* key, which no event
    // has revealed in `k`. Tokens signed with it would verify nowhere.
    expect(publicKey).not.toBe(authorityKey(0, 1))
  })

  test('refuses a log that does not fold rather than signing with a stale key', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate(seed, 0, did, inception.event)
    // A rotate that re-reveals the inception key instead of the pre-committed one: it does not
    // match the inception's `n`, so the fold rejects it.
    const forged = { ...rotate, event: { ...rotate.event, k: [inception.event.k[0]] } }

    expect(() => createControllerIdentity(seed, 0, [inception, forged])).toThrow(/invalid rotate/)
  })

  test('refuses an empty log', () => {
    expect(() => createControllerIdentity(seed, 0, [])).toThrow(/empty log/)
  })

  test('refuses a log whose first event is not an inception', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate(seed, 0, did, inception.event)

    expect(() => createControllerIdentity(seed, 0, [rotate])).toThrow(/must be an inception/)
  })

  test('refuses a seed that does not control this log', () => {
    const inception = createInception(seed, 0)
    const other = new Uint8Array(32).fill(9)

    expect(() => createControllerIdentity(other, 0, [inception])).toThrow(
      /does not match the current authority key/,
    )
  })

  test('refuses the wrong profile index for this log', () => {
    const inception = createInception(seed, 0)

    expect(() => createControllerIdentity(seed, 1, [inception])).toThrow(
      /does not match the current authority key/,
    )
  })

  test('refuses a capability-authorised revoke it cannot verify inline', () => {
    const { log } = capLog()

    expect(() => createControllerIdentity(seed, 0, log)).toThrow(/capability/)
  })
})

describe('createControllerIdentityAsync()', () => {
  test('signs from a log whose revoke the injected verifier authorises', async () => {
    const { did, log, inception } = capLog()
    const seen: Array<Array<string>> = []

    const identity = await createControllerIdentityAsync(seed, 0, log, {
      verifyCapability: async (capability, subject, target) => {
        seen.push([capability, subject, target])
        return true
      },
    })

    expect(identity.id).toBe(did)
    // The revoke establishes no key, so the identity still signs at the inception's position.
    expect(encodeKey(identity.publicKey, 'EdDSA')).toBe(inception.event.k[0])
    // The verifier is handed the capability, the controller it must name as `sub`, and the DID
    // being denied — passing anything else would authorise a revoke of the wrong device.
    expect(seen).toEqual([[cap, did, device]])

    const signed = await identity.signToken({ hello: 'world' })
    expect(signed.payload.iss).toBe(did)
  })

  test('refuses the same log when the verifier declines the capability', async () => {
    const { log } = capLog()

    await expect(
      createControllerIdentityAsync(seed, 0, log, { verifyCapability: async () => false }),
    ).rejects.toThrow(/capability does not authorise this revoke/)
  })

  test('refuses the same log when no verifier is supplied', async () => {
    const { log } = capLog()

    await expect(createControllerIdentityAsync(seed, 0, log)).rejects.toThrow(/needs a verifier/)
  })

  test('produces the same identity as the sync entry point for a log with no capability', async () => {
    const inception = createInception(seed, 0)
    const rotate = createRotate(seed, 0, didFromInception(inception.event), inception.event)
    const log = [inception, rotate]

    const identity = await createControllerIdentityAsync(seed, 0, log)

    expect(identity.id).toBe(createControllerIdentity(seed, 0, log).id)
    expect(encodeKey(identity.publicKey, 'EdDSA')).toBe(rotate.event.k[0])
  })

  test('keeps the sync guards — an empty log, a non-inception head, a foreign seed', async () => {
    const inception = createInception(seed, 0)

    await expect(createControllerIdentityAsync(seed, 0, [])).rejects.toThrow(/empty log/)
    await expect(
      createControllerIdentityAsync(seed, 0, [
        createRotate(seed, 0, didFromInception(inception.event), inception.event),
      ]),
    ).rejects.toThrow(/must be an inception/)
    await expect(
      createControllerIdentityAsync(new Uint8Array(32).fill(9), 0, [inception]),
    ).rejects.toThrow(/does not match the current authority key/)
  })
})
