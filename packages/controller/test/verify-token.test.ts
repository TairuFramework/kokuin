import { createUnsignedToken, signToken, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  createInception,
  createRevoke,
  createRotate,
  decodeKey,
  didFromInception,
} from '../src/events.js'
import { createControllerIdentity } from '../src/identity.js'
import { createControllerResolver } from '../src/resolver.js'
import { buildTwoKeyLog } from './two-key-log.js'

const seed = new Uint8Array(32).fill(7)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

describe('verifying a token issued by a did:kokuin: profile', () => {
  test('verifyToken accepts a token signed by the current authority key', async () => {
    const inception = createInception(seed, 0)
    const log = [inception]
    const did = didFromInception(inception.event)
    const resolver = createControllerResolver({ loadLog: async () => log })

    const identity = createControllerIdentity(seed, 0, log)
    const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))

    const verified = await verifyToken(token, { methods: [resolver] })
    expect(verified.payload.hello).toBe('world')
    expect(verified.payload.iss).toBe(did)
  })

  test('without the registry the same token is unresolvable', async () => {
    const inception = createInception(seed, 0)
    const log = [inception]
    const did = didFromInception(inception.event)

    const identity = createControllerIdentity(seed, 0, log)
    const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))

    // No `methods`: nothing can turn a did:kokuin: identifier into a key, so verification must
    // fail rather than succeed for some unrelated reason.
    await expect(verifyToken(token)).rejects.toThrow(`Unknown DID: ${did}`)
    // Control: the registry is the only difference between this and the test above.
    await expect(
      verifyToken(token, { methods: [createControllerResolver({ loadLog: async () => log })] }),
    ).resolves.toBeDefined()
  })

  test('a token signed by the pre-rotation key is rejected once the log has rotated', async () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate(seed, 0, did, inception.event)

    // Signed before the rotation, by an identity that only ever saw the inception.
    const stale = createControllerIdentity(seed, 0, [inception])
    const token = await signToken(stale, createUnsignedToken({ hello: 'world' }))

    const rotated = createControllerResolver({ loadLog: async () => [inception, rotate] })
    // The stale token names its own key in `kid`, and the rotation retired it, so the rejection
    // now comes from key selection rather than from the signature check. Either way the token
    // does not verify — which is the property this test exists for.
    await expect(verifyToken(token, { methods: [rotated] })).rejects.toThrow(
      /kid names a key outside the current set/,
    )

    // Control: the same token still verifies against a resolver whose log stops at the inception,
    // so the rejection above is the rotation retiring the key and not a malformed token.
    const preRotation = createControllerResolver({ loadLog: async () => [inception] })
    await expect(verifyToken(token, { methods: [preRotation] })).resolves.toBeDefined()
  })

  test('a token signed after a revoke verifies — the key position is not the event position', async () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    // A revoke advances `seq` to 1 while establishing no key, so the fold's `gen`/`seq` and
    // `keyGen`/`keySeq` diverge here for the first time. Deriving at `gen`/`seq` yields the
    // pre-committed *next* key, which the resolver never answers with — the signature would not
    // verify. This is the scenario the distinction exists for, checked end to end rather than at
    // the key bytes.
    const revoke = createRevoke(seed, 0, did, inception.event, device, { gen: 0, seq: 0 })
    const log = [inception, revoke]
    const resolver = createControllerResolver({ loadLog: async () => log })

    const identity = createControllerIdentity(seed, 0, log)
    const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))

    const verified = await verifyToken(token, { methods: [resolver] })
    expect(verified.payload.iss).toBe(did)
    expect(verified.payload.hello).toBe('world')
  })

  test('a token signed under a kid verifies end to end', async () => {
    // A hand-built two-key inception — see `two-key-log.ts`. The controller signs with `k[1]`.
    const { did, log, cosignerKey, controllerKey } = buildTwoKeyLog(seed)
    const resolver = createControllerResolver({ loadLog: async () => log })

    const identity = createControllerIdentity(seed, 0, log)
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

  test('a token signed after the rotation verifies against the rotated log', async () => {
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate(seed, 0, did, inception.event)
    const log = [inception, rotate]
    const resolver = createControllerResolver({ loadLog: async () => log })

    const identity = createControllerIdentity(seed, 0, log)
    const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))

    const verified = await verifyToken(token, { methods: [resolver] })
    // The DID is unchanged across the rotation — the identifier is the inception digest.
    expect(verified.payload.iss).toBe(did)
    expect(verified.payload.hello).toBe('world')
  })
})
