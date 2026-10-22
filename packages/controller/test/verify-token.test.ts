import { createUnsignedToken, signToken, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createInception, createReset, createRotate, didFromInception } from '../src/events.js'
import { createControllerIdentity } from '../src/identity.js'
import { decodeKey } from '../src/keys.js'
import { createControllerResolver } from '../src/resolver.js'
import { buildTwoKeyLog } from './two-key-log.js'

const seed = new Uint8Array(32).fill(7)

describe('verifying a token issued by a did:kokuin: profile', () => {
  test('verifyToken accepts a token signed by the current authority key', async () => {
    const inception = createInception(seed, 0)
    const log = [inception]
    const did = didFromInception(inception.event)
    const resolver = createControllerResolver({ loadLog: async () => ({ chain: log, events: [] }) })

    const identity = createControllerIdentity({ seed, profile: 0, log: { chain: log, events: [] } })
    const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))

    const verified = await verifyToken(token, { methods: [resolver] })
    expect(verified.payload.hello).toBe('world')
    expect(verified.payload.iss).toBe(did)
  })

  test('without the registry the same token is unresolvable', async () => {
    const inception = createInception(seed, 0)
    const log = [inception]
    const did = didFromInception(inception.event)

    const identity = createControllerIdentity({ seed, profile: 0, log: { chain: log, events: [] } })
    const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))

    // No `methods`: nothing can turn a did:kokuin: identifier into a key, so verification must
    // fail rather than succeed for some unrelated reason.
    await expect(verifyToken(token)).rejects.toThrow(`Unknown DID: ${did}`)
    // Control: the registry is the only difference between this and the test above.
    await expect(
      verifyToken(token, {
        methods: [createControllerResolver({ loadLog: async () => ({ chain: log, events: [] }) })],
      }),
    ).resolves.toBeDefined()
  })

  test('a token signed by the pre-rotation key is rejected once the log has reset', async () => {
    const inception = createInception(seed, 0)
    const reset = createReset(seed, 0, 1)

    // Signed before the reset, by an identity that only ever saw the inception.
    const stale = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [] },
    })
    const token = await signToken(stale, createUnsignedToken({ hello: 'world' }))

    const recovered = createControllerResolver({
      loadLog: async () => ({ chain: [inception, reset], events: [] }),
    })
    // A reset is the one event that discards everything under the prior generation *even for a
    // caller that opted into historic resolution* — a rotate discards it only for the default,
    // which `generation-lifecycle.test.ts` covers from the other side.
    await expect(verifyToken(token, { methods: [recovered], historic: true })).rejects.toThrow(
      /kid names a key outside the current generation/,
    )
    await expect(verifyToken(token, { methods: [recovered] })).rejects.toThrow(
      /kid names a key that is not current/,
    )

    // Control: the same token still verifies against a resolver whose log stops at the inception,
    // so the rejection above is the generation bump and not a malformed token.
    const preReset = createControllerResolver({
      loadLog: async () => ({ chain: [inception], events: [] }),
    })
    await expect(verifyToken(token, { methods: [preReset] })).resolves.toBeDefined()
  })

  test('a token signed under a kid verifies end to end', async () => {
    // A hand-built two-key inception — see `two-key-log.ts`. The controller signs with `k[1]`.
    const { did, log, cosignerKey, controllerKey } = buildTwoKeyLog(seed)
    const resolver = createControllerResolver({ loadLog: async () => ({ chain: log, events: [] }) })

    const identity = createControllerIdentity({ seed, profile: 0, log: { chain: log, events: [] } })
    const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))
    expect(token.header.kid).toBe(`#${controllerKey}`)

    const verified = await verifyToken(token, { methods: [resolver] })
    expect(verified.payload.iss).toBe(did)
    expect(verified.payload.hello).toBe('world')
    // What the kid bought: with no kid this resolver answers with the co-signer's key, so a
    // verification that succeeded on `keys[0]` would have failed. The signature was checked
    // against the key the header named.
    expect(verified.verifiedPublicKey).toEqual(decodeKey(controllerKey).publicKey)
    const withoutKid = await resolver.resolve(did, {})
    expect(withoutKid.publicKey).toEqual(decodeKey(cosignerKey).publicKey)
  })

  test('a token signed by a revoked key is rejected under historic resolution too', async () => {
    // The end-to-end shape of the escalation `packages/capability/test/own-historic-mint.test.ts`
    // demonstrates, at the plain-token layer where there is no capability chain to blame. A leaked
    // key that the profile has rotated away still verifies with `historic: true` — it must, or
    // every already-issued capability dies at the next rotate. Denying the key is the event that
    // ends that, and this is the whole point of the feature.
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const leaked = inception.event.k[0]

    const thief = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception], events: [] },
    })
    const token = await signToken(thief, createUnsignedToken({ hello: 'world' }))
    expect(token.header.kid).toBe(`#${leaked}`)

    // Control: after the rotate alone, the historic question still answers yes.
    const rotated = createControllerResolver({
      loadLog: async () => ({ chain: [inception, rotate], events: [] }),
    })
    await expect(verifyToken(token, { methods: [rotated], historic: true })).resolves.toBeDefined()

    const revoke = createRotate({
      seed,
      profile: 0,
      did,
      prior: rotate.event,
      snapshot: { members: [], deny: [`#${leaked}`] },
    })
    const revoked = createControllerResolver({
      loadLog: async () => ({ chain: [inception, rotate, revoke], events: [] }),
    })
    // Control: the same third rotate with an empty snapshot leaves the historic answer at yes, so
    // what refuses the token below is the denial and not the extra rotate.
    const undenied = createRotate({
      seed,
      profile: 0,
      did,
      prior: rotate.event,
      snapshot: { members: [], deny: [] },
    })
    const twiceRotated = createControllerResolver({
      loadLog: async () => ({ chain: [inception, rotate, undenied], events: [] }),
    })
    await expect(
      verifyToken(token, { methods: [twiceRotated], historic: true }),
    ).resolves.toBeDefined()
    await expect(verifyToken(token, { methods: [revoked], historic: true })).rejects.toThrow(
      /kid names a key the controller has revoked/,
    )

    // Second control: the same log, and a token signed by the key the profile actually holds,
    // still verifies both ways — so the rejection is the denial, not the third event.
    const owner = createControllerIdentity({
      seed,
      profile: 0,
      log: { chain: [inception, rotate, revoke], events: [] },
    })
    const live = await signToken(owner, createUnsignedToken({ hello: 'world' }))
    await expect(verifyToken(live, { methods: [revoked] })).resolves.toBeDefined()
    await expect(verifyToken(live, { methods: [revoked], historic: true })).resolves.toBeDefined()
  })

  test('a token signed after the rotation verifies against the rotated log', async () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate({
      seed,
      profile: 0,
      did,
      prior: inception.event,
      snapshot: { members: [], deny: [] },
    })
    const log = [inception, rotate]
    const resolver = createControllerResolver({ loadLog: async () => ({ chain: log, events: [] }) })

    const identity = createControllerIdentity({ seed, profile: 0, log: { chain: log, events: [] } })
    const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))

    const verified = await verifyToken(token, { methods: [resolver] })
    // The DID is unchanged across the rotation — the identifier is the inception digest.
    expect(verified.payload.iss).toBe(did)
    expect(verified.payload.hello).toBe('world')
  })
})
