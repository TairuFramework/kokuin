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
    ]) {
      expect(controller).toHaveProperty(name)
    }
  })

  test('does not leak internal helpers', () => {
    expect(controller).not.toHaveProperty('signEvent')
  })
})
