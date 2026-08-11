import { describe, expect, test } from 'vitest'

import * as controller from '../src/index.js'

describe('public surface', () => {
  test('exports everything downstream repos need', () => {
    for (const name of [
      'VERSION_TAG',
      'canonicalBytes',
      'digestOf',
      'verifyDigest',
      // `canonicalBytes` throws above the bound, so a consumer canonicalizing untrusted input of
      // its own needs both the limit and the total predicate the fold uses to stay off it.
      'MAX_CANONICAL_DEPTH',
      'withinCanonicalDepth',
      'authorityPath',
      'agreementPath',
      'recoveryPath',
      'deriveKeyMaterial',
      'deriveKeyPair',
      'createInception',
      'createRotate',
      'createReset',
      'createRevoke',
      'createRevokeWithKey',
      'didFromInception',
      'DID_PREFIX',
      'encodeKey',
      'decodeKey',
      'tryDecodeKey',
      'verifyInception',
      'verifyRotate',
      'verifyReset',
      'verifyRevoke',
      'verifySignatures',
      'foldLog',
      'foldLogAsync',
      'keyStateAt',
      'resolveBranches',
      'enumerateProfiles',
      'handleForDID',
      'createControllerResolver',
      'createControllerIdentity',
      'createControllerIdentityAsync',
      // The fold's capability-revoke failure reasons. `@kokuin/capability` asserts on these by
      // string literal across the package boundary, so they are a contract either way.
      'CAPABILITY_VERIFIER_FAILED',
      'CAPABILITY_VERIFIER_MALFORMED_ANSWER',
      'REVOKE_NOT_SIGNED_BY_AUDIENCE',
    ]) {
      expect(controller).toHaveProperty(name)
    }
  })

  test('does not leak internal helpers', () => {
    expect(controller).not.toHaveProperty('signEvent')
    // The audience-signature check the fold performs on a capability-authorised revoke. Only the
    // fold calls it, and the package's API is already changing here — kept internal rather than
    // widening the published surface for a helper nothing downstream needs.
    expect(controller).not.toHaveProperty('verifyEventSignedBy')
  })
})
