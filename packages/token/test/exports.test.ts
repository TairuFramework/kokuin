import { describe, expect, it } from 'vitest'

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
})
