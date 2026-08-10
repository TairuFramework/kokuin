import type { ResolvedSigningKey } from '@kokuin/token'
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
import { buildTwoKeyLog } from './two-key-log.js'

const seed = new Uint8Array(32).fill(7)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
// Not the controller's seed: the revoke below is signed by a delegate, so only the capability it
// carries can authorise it.
const delegateSeed = new Uint8Array(32).fill(3)
const cap = 'eyJ.delegated.revoke'
/** What the capability's `aud` resolves to: the key the delegate signs the revoke with. */
const delegateKey: ResolvedSigningKey = {
  alg: 'EdDSA',
  publicKey: deriveKeyPair(delegateSeed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
}

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
      /is not one of the current authority keys/,
    )
  })

  test('refuses the wrong profile index for this log', () => {
    const inception = createInception(seed, 0)

    expect(() => createControllerIdentity(seed, 1, [inception])).toThrow(
      /is not one of the current authority keys/,
    )
  })

  test('refuses a capability-authorised revoke it cannot verify inline', () => {
    const { log } = capLog()

    expect(() => createControllerIdentity(seed, 0, log)).toThrow(/capability/)
  })
})

describe('createControllerIdentity() kid', () => {
  test('stamps the kid of the key it signs with', async () => {
    const inception = createInception(seed, 0)
    const identity = createControllerIdentity(seed, 0, [inception])

    const signed = await identity.signToken({ hello: 'world' })
    expect(signed.header.kid).toBe(`#${inception.event.k[0]}`)
  })

  test('stamps the rotated key after a rotation, not the retired one', async () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate(seed, 0, did, inception.event)

    const identity = createControllerIdentity(seed, 0, [inception, rotate])
    const signed = await identity.signToken({ hello: 'world' })

    expect(signed.header.kid).toBe(`#${rotate.event.k[0]}`)
    expect(signed.header.kid).not.toBe(`#${inception.event.k[0]}`)
  })

  test('signs with the seed-derived key when the set publishes another key first', async () => {
    // A hand-built two-key inception — see `two-key-log.ts`. The controller's key is `k[1]`.
    const { log, cosignerKey, controllerKey } = buildTwoKeyLog(seed)
    const identity = createControllerIdentity(seed, 0, log)

    expect(encodeKey(identity.publicKey, 'EdDSA')).toBe(controllerKey)
    const signed = await identity.signToken({ hello: 'world' })
    expect(signed.header.kid).toBe(`#${controllerKey}`)
    // `keys[0]` is the co-signer's, whose private key this identity does not hold: stamping it
    // would name a key the token was not signed with.
    expect(signed.header.kid).not.toBe(`#${cosignerKey}`)
  })

  test('keeps caller header fields alongside the kid', async () => {
    const inception = createInception(seed, 0)
    const identity = createControllerIdentity(seed, 0, [inception])

    const signed = await identity.signToken(
      { hello: 'world' },
      { header: { cty: 'application/x' } },
    )
    expect(signed.header.cty).toBe('application/x')
    expect(signed.header.kid).toBe(`#${inception.event.k[0]}`)
  })

  test('an explicit undefined kid in the caller header does not erase the stamp', async () => {
    const inception = createInception(seed, 0)
    const identity = createControllerIdentity(seed, 0, [inception])

    // Pins the spread order: under `{ kid, ...options.header }` a header carrying an explicit
    // `undefined` kid overwrites the stamp — and the mismatch guard does not fire, since
    // `undefined != null` is false — so the token would name no key at all.
    const signed = await identity.signToken({ hello: 'world' }, { header: { kid: undefined } })
    expect(signed.header.kid).toBe(`#${inception.event.k[0]}`)
  })

  test('accepts a caller kid that names the key it signs with', async () => {
    const inception = createInception(seed, 0)
    const identity = createControllerIdentity(seed, 0, [inception])
    const kid = `#${inception.event.k[0]}`

    const signed = await identity.signToken({ hello: 'world' }, { header: { kid } })
    expect(signed.header.kid).toBe(kid)
  })

  test('refuses a caller kid naming any other key', async () => {
    const { log, cosignerKey, controllerKey } = buildTwoKeyLog(seed)
    const identity = createControllerIdentity(seed, 0, log)

    // The co-signer's key is in the published set, so the resolver would accept it — but this
    // identity cannot sign with it. Silently dropping the caller's kid would mint a token whose
    // header names a key that did not produce the signature.
    await expect(
      identity.signToken({ hello: 'world' }, { header: { kid: `#${cosignerKey}` } }),
    ).rejects.toThrow(
      `Controller identity: cannot sign under kid #${cosignerKey}, this identity holds #${controllerKey}`,
    )
  })

  test('refuses a caller kid passed as the key-selection option too', async () => {
    const { log, cosignerKey, controllerKey } = buildTwoKeyLog(seed)
    const identity = createControllerIdentity(seed, 0, log)

    // `SignTokenOptions.kid` selects among a multi-key identity's keys, and the DID-bound identity
    // underneath ignores it outright. Ignoring it here would be the same silent mis-selection as
    // dropping a header kid, one spelling over.
    await expect(
      identity.signToken({ hello: 'world' }, { kid: `#${cosignerKey}` }),
    ).rejects.toThrow(
      `Controller identity: cannot sign under kid #${cosignerKey}, this identity holds #${controllerKey}`,
    )
  })
})

describe('createControllerIdentityAsync()', () => {
  test('signs from a log whose revoke the injected verifier authorises', async () => {
    const { did, log, inception } = capLog()
    const seen: Array<Array<string>> = []

    const identity = await createControllerIdentityAsync(seed, 0, log, {
      verifyCapability: async (capability, subject, target) => {
        seen.push([capability, subject, target])
        return delegateKey
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
      createControllerIdentityAsync(seed, 0, log, { verifyCapability: async () => null }),
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

    // Including the header it stamps: both entry points build the identity the same way.
    const signed = await identity.signToken({ hello: 'world' })
    expect(signed.header.kid).toBe(`#${rotate.event.k[0]}`)
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
    ).rejects.toThrow(/is not one of the current authority keys/)
  })
})
