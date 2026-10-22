import { isFullIdentity } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import { createRevoke } from '../src/epoch-events.js'
import {
  createInception,
  createRotate,
  didFromInception,
  type InceptionEvent,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { createControllerIdentity } from '../src/identity.js'
import { encodeKey } from '../src/keys.js'
import type { ControllerLog } from '../src/log.js'
import { buildTwoKeyLog } from './two-key-log.js'

const seed = new Uint8Array(32).fill(7)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function authorityKey(gen: number, seq: number): string {
  return encodeKey(deriveKeyPair(seed, authorityPath(0, gen, seq), 'EdDSA').publicKey, 'EdDSA')
}

describe('createControllerIdentity()', () => {
  test('binds the identity to the did:kokuin: DID, not a did:key:', async () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const identity = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [] },
    })

    expect(identity.id).toBe(did)

    const signed = await identity.signToken({ hello: 'world' })
    expect(signed.payload.iss).toBe(did)
  })

  test('keeps the payload issuer guard', async () => {
    const identity = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [createInception(seed, 0)], events: [] },
    })
    await expect(
      identity.signToken({ iss: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' }),
    ).rejects.toThrow(/issuer does not match signer/)
  })

  test('signs with the rotated key after a rotation, not the inception key', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })

    const identity = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception, rotate], events: [] },
    })
    const publicKey = encodeKey(identity.publicKey, 'EdDSA')

    // The key the rotate published, which is the only one the resolver will answer with.
    expect(publicKey).toBe(rotate.event.k[0])
    expect(publicKey).toBe(authorityKey(0, 1))
    // The inception key is retired: signing with it after a rotation is the failure a rotation
    // exists to prevent.
    expect(publicKey).not.toBe(inception.event.k[0])
    expect(publicKey).not.toBe(authorityKey(0, 0))
  })

  test('refuses a log that does not fold rather than signing with a stale key', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    // A rotate that re-reveals the inception key instead of the pre-committed one: it does not
    // match the inception's `n`, so the fold rejects it.
    const forged = { ...rotate, event: { ...rotate.event, k: [inception.event.k[0]] } }

    expect(() =>
      createControllerIdentity({
        seed,
        profile: 0,
        log: { chain: [inception, forged], events: [] },
      }),
    ).toThrow(/invalid rotate/)
  })

  test('refuses an empty log', () => {
    expect(() =>
      createControllerIdentity({ seed, profile: 0, log: { chain: [], events: [] } }),
    ).toThrow(/empty log/)
  })

  test('refuses a bare event array, the shape a log had before epochs', () => {
    const legacy = [createInception(seed, 0)] as unknown as ControllerLog
    expect(() => createControllerIdentity({ seed, profile: 0, log: legacy })).toThrow(
      /malformed log/,
    )
  })

  test('signs from the chain whatever epoch events ride along', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const head = foldLog(did, { chain: [inception], events: [] })
    if (!head.ok) throw new Error('did not fold')
    const revoke = createRevoke({
      signer: { root: { seed, profile: 0 } },
      did,
      head: head.head,
      parents: [head.head.epoch],
      target: device,
    })
    const bare = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [] },
    })
    const withEpoch = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [revoke, { not: 'an event' }] as ControllerLog['events'] },
    })
    expect(withEpoch.publicKey).toEqual(bare.publicKey)
  })

  test('refuses a log whose first event is not an inception', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })

    expect(() =>
      createControllerIdentity({ seed, profile: 0, log: { chain: [rotate], events: [] } }),
    ).toThrow(/must be an inception/)
  })

  test('refuses a seed that does not control this log', () => {
    const inception = createInception(seed, 0)
    const other = new Uint8Array(32).fill(9)

    expect(() =>
      createControllerIdentity({
        seed: other,
        profile: 0,
        log: { chain: [inception], events: [] },
      }),
    ).toThrow(/is not one of the current authority keys/)
  })

  test('refuses the wrong profile index for this log', () => {
    const inception = createInception(seed, 0)

    expect(() =>
      createControllerIdentity({ seed, profile: 1, log: { chain: [inception], events: [] } }),
    ).toThrow(/is not one of the current authority keys/)
  })

  test('refuses a log carrying a chain revoke, which the root chain no longer has', () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const revoke = {
      event: {
        v: 1,
        t: 'rev',
        i: did,
        g: 0,
        s: 1,
        p: digestOf(inception.event),
        crit: true,
        x: device,
      },
      sigs: ['AAAA'],
    } as unknown as SignedEvent
    const log = [inception, revoke]

    expect(() =>
      createControllerIdentity({ seed, profile: 0, log: { chain: log, events: [] } }),
    ).toThrow(/unknown critical event type: rev/)
  })
})

describe('createControllerIdentity() kid', () => {
  test('stamps the kid of the key it signs with', async () => {
    const inception = createInception(seed, 0)
    const identity = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [] },
    })

    const signed = await identity.signToken({ hello: 'world' })
    expect(signed.header.kid).toBe(`#${inception.event.k[0]}`)
  })

  test('stamps the rotated key after a rotation, not the retired one', async () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })

    const identity = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception, rotate], events: [] },
    })
    const signed = await identity.signToken({ hello: 'world' })

    expect(signed.header.kid).toBe(`#${rotate.event.k[0]}`)
    expect(signed.header.kid).not.toBe(`#${inception.event.k[0]}`)
  })

  test('signs with the seed-derived key when the set publishes another key first', async () => {
    // A hand-built two-key inception — see `two-key-log.ts`. The controller's key is `k[1]`.
    const { log, cosignerKey, controllerKey } = buildTwoKeyLog(seed)
    const identity = createControllerIdentity({ seed, profile: 0, log: { chain: log, events: [] } })

    expect(encodeKey(identity.publicKey, 'EdDSA')).toBe(controllerKey)
    const signed = await identity.signToken({ hello: 'world' })
    expect(signed.header.kid).toBe(`#${controllerKey}`)
    // `keys[0]` is the co-signer's, whose private key this identity does not hold: stamping it
    // would name a key the token was not signed with.
    expect(signed.header.kid).not.toBe(`#${cosignerKey}`)
  })

  test('keeps caller header fields alongside the kid', async () => {
    const inception = createInception(seed, 0)
    const identity = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [] },
    })

    const signed = await identity.signToken(
      { hello: 'world' },
      { header: { cty: 'application/x' } },
    )
    expect(signed.header.cty).toBe('application/x')
    expect(signed.header.kid).toBe(`#${inception.event.k[0]}`)
  })

  test('an explicit undefined kid in the caller header does not erase the stamp', async () => {
    const inception = createInception(seed, 0)
    const identity = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [] },
    })

    // Pins the spread order: under `{ kid, ...options.header }` a header carrying an explicit
    // `undefined` kid overwrites the stamp — and the mismatch guard does not fire, since
    // `undefined != null` is false — so the token would name no key at all.
    const signed = await identity.signToken({ hello: 'world' }, { header: { kid: undefined } })
    expect(signed.header.kid).toBe(`#${inception.event.k[0]}`)
  })

  test('accepts a caller kid that names the key it signs with', async () => {
    const inception = createInception(seed, 0)
    const identity = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [] },
    })
    const kid = `#${inception.event.k[0]}`

    const signed = await identity.signToken({ hello: 'world' }, { header: { kid } })
    expect(signed.header.kid).toBe(kid)
  })

  test('refuses a caller kid naming any other key', async () => {
    const { log, cosignerKey, controllerKey } = buildTwoKeyLog(seed)
    const identity = createControllerIdentity({ seed, profile: 0, log: { chain: log, events: [] } })

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
    const identity = createControllerIdentity({ seed, profile: 0, log: { chain: log, events: [] } })

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

describe('controller identity is a FullIdentity', () => {
  test('the seed path yields signing and key agreement bound to the controller DID', async () => {
    const seed = new Uint8Array(32).fill(11)
    const profile = 0
    const inception = createInception(seed, profile)
    const did = didFromInception(inception.event)

    const identity = createControllerIdentity({
      seed,
      profile,
      log: { chain: [inception], events: [] },
    })

    expect(identity.id).toBe(did)
    expect(isFullIdentity(identity)).toBe(true)
    // Signing still stamps the authority kid. `event.k[0]` is already the multibase-encoded key.
    const token = await identity.signToken({ sub: 'x' })
    expect(token.header.kid).toBe(`#${inception.event.k[0]}`)
  })

  test('rejects a state whose agreement set omits the derived key', () => {
    const seed = new Uint8Array(32).fill(12)
    const profile = 0
    // Hand-built and re-signed (see `two-key-log.ts`), publishing a valid-but-foreign agreement
    // key: mutating `ka` on an already-signed inception without re-signing would fail the fold's
    // signature check first, not the agreement-membership check this test targets.
    const current = deriveKeyPair(seed, authorityPath(profile, 0, 0), 'EdDSA')
    const next = deriveKeyPair(seed, authorityPath(profile, 0, 1), 'EdDSA')
    const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')
    const foreignAgreement = deriveKeyPair(
      new Uint8Array(32).fill(13),
      agreementPath(profile, 0, 0),
      'X25519',
    )
    const event: InceptionEvent = {
      v: 1,
      t: 'icp',
      g: 0,
      s: 0,
      crit: true,
      k: [encodeKey(current.publicKey, 'EdDSA')],
      ka: [encodeKey(foreignAgreement.publicKey, 'X25519')],
      n: [digestOf(encodeKey(next.publicKey, 'EdDSA'))],
      kt: 1,
      nt: 1,
      r: digestOf(encodeKey(recovery.publicKey, 'EdDSA')),
    }
    const tampered = { event, sigs: signEvent(event, [current.privateKey]) }

    expect(() =>
      createControllerIdentity({ seed, profile, log: { chain: [tampered], events: [] } }),
    ).toThrow(/agreement key is not one of the current agreement keys/)
  })
})
