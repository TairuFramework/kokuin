import { describe, expect, test } from 'vitest'

import * as controller from '../src/index.js'

describe('public surface', () => {
  test('exports everything downstream repos need', () => {
    for (const name of [
      'VERSION_TAG',
      'canonicalBytes',
      'digestOf',
      'verifyDigest',
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
