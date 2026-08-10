import { describe, expect, it } from 'vitest'

import type { AgreementAlgorithm, ResolvedAgreementKey } from '../src/index.js'
import * as token from '../src/index.js'

describe('package exports', () => {
  it.each([
    'encodeMultibase',
    'decodeMultibase',
    'multihashSHA256',
    'verifyMultihash',
    'encodePeer4',
    'decodePeer4',
    'isPeer4',
    'getPeer4ShortForm',
    'validateDIDDoc',
    'createInMemoryDIDCache',
    'resolveIssuer',
    'createIdentity',
    'createKeyAgreementIdentity',
    'isKeyAgreementIdentity',
    // A value export, not type-only: `toBeDefined` below would be vacuous for a type.
    'createSigningIdentityForDID',
    // 'createRotationAssertion' removed — see @kokuin/controller for did:kokuin controller logs.
  ])('exports %s', (name) => {
    expect((token as Record<string, unknown>)[name]).toBeDefined()
  })

  it.each([
    // JWE moved to @kokuin/jwe -- verify-only consumers of @kokuin/token no longer pay for
    // @noble/ciphers.
    'concatKDF',
    'createTokenEncrypter',
    'decryptToken',
    'deriveSharedSecret',
    'encryptToken',
    'unwrapEnvelope',
    'wrapEnvelope',
    // DecryptingIdentity was renamed to KeyAgreementIdentity and lost its `decrypt` sugar.
    'createDecryptingIdentity',
    'isDecryptingIdentity',
    // Rotation chains superseded by did:kokuin event logs.
    'createRotationAssertion',
    'RotationPayload',
  ])('does not export %s', (name) => {
    expect((token as Record<string, unknown>)[name]).toBeUndefined()
  })

  it('exports the agreement key resolution types from the barrel', () => {
    // Type-only exports have no runtime presence to assert with `toBeDefined`. This import
    // resolving at all is the check: `pnpm run test:types` fails to compile if either type is
    // dropped from `index.ts`.
    const alg: AgreementAlgorithm = 'X25519'
    const key: ResolvedAgreementKey = { alg, publicKey: new Uint8Array() }
    expect(key.alg).toBe('X25519')
  })
})
