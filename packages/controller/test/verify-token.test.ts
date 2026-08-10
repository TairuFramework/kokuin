import { createUnsignedToken, signToken, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createInception, createRotate, didFromInception } from '../src/events.js'
import { createControllerIdentity } from '../src/identity.js'
import { createControllerResolver } from '../src/resolver.js'

const seed = new Uint8Array(32).fill(7)

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
    await expect(verifyToken(token, { methods: [rotated] })).rejects.toThrow(/Invalid signature/)

    // Control: the same token still verifies against a resolver whose log stops at the inception,
    // so the rejection above is the rotation retiring the key and not a malformed token.
    const preRotation = createControllerResolver({ loadLog: async () => [inception] })
    await expect(verifyToken(token, { methods: [preRotation] })).resolves.toBeDefined()
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
