import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { createSigningIdentity, createSigningIdentityForDID } from '../src/identity.js'
import type { DIDMethodResolver } from '../src/method.js'
import { verifyToken } from '../src/token.js'
import type { DIDString } from '../src/types.js'
import { stringifyToken } from '../src/utils.js'

// A method whose keys are not recoverable from the identifier. Nothing in this package can
// resolve it without a registry entry, which is the point.
const did = 'did:kokuin:zTestProfile' as DIDString

function buildProfile(): {
  identity: ReturnType<typeof createSigningIdentityForDID>
  resolver: DIDMethodResolver
} {
  const privateKey = ed25519.utils.randomSecretKey()
  const identity = createSigningIdentityForDID(did, privateKey)
  const resolver: DIDMethodResolver = {
    method: 'kokuin',
    resolve: async (requested: string) => {
      if (requested !== did) {
        throw new Error(`Unknown DID: ${requested}`)
      }
      return { alg: 'EdDSA', publicKey: identity.publicKey }
    },
  }
  return { identity, resolver }
}

describe('VerifyTokenOptions.methods', () => {
  test('verifies a token object whose iss only a registered method can resolve', async () => {
    const { identity, resolver } = buildProfile()
    const token = await identity.signToken({ hello: 'world' })

    const verified = await verifyToken(token, { methods: [resolver] })
    expect(verified.payload.iss).toBe(did)
    expect(verified.verifiedPublicKey).toEqual(identity.publicKey)
  })

  test('rejects the same token object when no registry is passed', async () => {
    const { identity } = buildProfile()
    const token = await identity.signToken({ hello: 'world' })

    await expect(verifyToken(token)).rejects.toThrow(`Unknown DID: ${did}`)
  })

  test('verifies a compact-string token — the form capability chains carry', async () => {
    const { identity, resolver } = buildProfile()
    // Serialized links are what `checkCapability` and `checkDelegationChain` hand to
    // `verifyToken`, so the string path is the live one for chain verification, not an edge case.
    const compact = stringifyToken(await identity.signToken({ hello: 'world' }))

    const verified = await verifyToken(compact, { methods: [resolver] })
    expect(verified.payload.iss).toBe(did)
    expect(verified.verifiedPublicKey).toEqual(identity.publicKey)
  })

  test('rejects the same compact-string token when no registry is passed', async () => {
    const { identity } = buildProfile()
    const compact = stringifyToken(await identity.signToken({ hello: 'world' }))

    await expect(verifyToken(compact)).rejects.toThrow(`Unknown DID: ${did}`)
  })

  test('uses the key the method resolved, not one recovered from the token', async () => {
    const { identity, resolver } = buildProfile()
    const compact = stringifyToken(await identity.signToken({ hello: 'world' }))
    // Same DID, different key: if verification consulted anything other than the registry's
    // answer, this would still pass.
    const impostor: DIDMethodResolver = {
      method: 'kokuin',
      resolve: async () => ({
        alg: 'EdDSA',
        publicKey: ed25519.getPublicKey(ed25519.utils.randomSecretKey()),
      }),
    }

    await expect(verifyToken(compact, { methods: [impostor] })).rejects.toThrow('Invalid signature')
    // Control: only the resolved key differs between this and the passing test above.
    await expect(verifyToken(compact, { methods: [resolver] })).resolves.toBeDefined()
  })

  test('leaves did:key alone — a registry with no matching method is not consulted', async () => {
    const { resolver } = buildProfile()
    const identity = createSigningIdentity(ed25519.utils.randomSecretKey())
    const compact = stringifyToken(await identity.signToken({ hello: 'world' }))

    // `resolve` throws for anything but the kokuin DID, so reaching it here would fail the test.
    const verified = await verifyToken(compact, { methods: [resolver] })
    expect(verified.payload.iss).toBe(identity.id)
  })
})

describe('VerifyTokenOptions.historic', () => {
  // A method whose key set rotates: `resolve` answers only for the current key, `resolveHistoric`
  // for either. That is the shape `did:kokuin:` has, spelled out here so the option's behaviour is
  // pinned in the package that owns it rather than only where it is consumed.
  function buildRotating() {
    const oldKey = ed25519.utils.randomSecretKey()
    const newKey = ed25519.utils.randomSecretKey()
    const retired = createSigningIdentityForDID(did, oldKey)
    const current = createSigningIdentityForDID(did, newKey)
    const resolver: DIDMethodResolver = {
      method: 'kokuin',
      resolve: async (requested: string) => {
        if (requested !== did) {
          throw new Error(`Unknown DID: ${requested}`)
        }
        return { alg: 'EdDSA', publicKey: current.publicKey }
      },
      resolveHistoric: async (requested: string, header) => {
        if (requested !== did) {
          throw new Error(`Unknown DID: ${requested}`)
        }
        return {
          alg: 'EdDSA',
          publicKey: header.kid === '#retired' ? retired.publicKey : current.publicKey,
        }
      },
    }
    return { retired, current, resolver }
  }

  test('a token from a rotated-away key is rejected by default and accepted under the opt-in', async () => {
    const { retired, resolver } = buildRotating()
    const token = await retired.signToken({ hello: 'world' }, { header: { kid: '#retired' } })

    await expect(verifyToken(token, { methods: [resolver] })).rejects.toThrow(/Invalid signature/)
    await expect(
      verifyToken(token, { methods: [resolver], historic: true }),
    ).resolves.toMatchObject({ payload: { hello: 'world' } })
  })

  test('control: a token from the current key verifies under both', async () => {
    // So the rejection above is the key being retired and not the option breaking verification.
    const { current, resolver } = buildRotating()
    const token = await current.signToken({ hello: 'world' })

    await expect(verifyToken(token, { methods: [resolver] })).resolves.toBeDefined()
    await expect(verifyToken(token, { methods: [resolver], historic: true })).resolves.toBeDefined()
  })

  test('a historically verified token object is re-checked when handed back without the opt-in', async () => {
    // The `verifiedTokens` fast path must not launder the weaker check into the stronger one: the
    // same object, verified once historically, is asked the current-key question and refused.
    const { retired, resolver } = buildRotating()
    const token = await retired.signToken({ hello: 'world' }, { header: { kid: '#retired' } })
    const verified = await verifyToken(token, { methods: [resolver], historic: true })

    await expect(verifyToken(verified, { methods: [resolver] })).rejects.toThrow(
      /Invalid signature/,
    )
    // Control: the same object re-verified historically still takes the fast path and passes.
    await expect(
      verifyToken(verified, { methods: [resolver], historic: true }),
    ).resolves.toBeDefined()
  })

  test('a strictly verified token object stays verified when re-checked historically', async () => {
    // The other direction needs no re-check: the strict answer already implies the loose one.
    const { current, resolver } = buildRotating()
    const token = await current.signToken({ hello: 'world' })
    const verified = await verifyToken(token, { methods: [resolver] })

    await expect(
      verifyToken(verified, { methods: [resolver], historic: true }),
    ).resolves.toBeDefined()
  })

  test('a serialized token is unaffected by any of this — it is verified from scratch', async () => {
    const { retired, resolver } = buildRotating()
    const token = await retired.signToken({ hello: 'world' }, { header: { kid: '#retired' } })
    const wire = stringifyToken(token)

    await expect(verifyToken(wire, { methods: [resolver] })).rejects.toThrow(/Invalid signature/)
    await expect(verifyToken(wire, { methods: [resolver], historic: true })).resolves.toBeDefined()
  })
})
