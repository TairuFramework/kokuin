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
      // Depth is only one of the ways `canonicalBytes` throws, and the other one — a non-finite
      // number — reaches it straight off the wire. This is the predicate that answers the whole
      // question, and the one the fold's envelope guard asks.
      'isCanonicalizable',
      'authorityPath',
      'agreementPath',
      'recoveryPath',
      'deriveKeyMaterial',
      'deriveKeyPair',
      'createInception',
      'createRotate',
      'createReset',
      // A deny entry may name a key instead of a DID. Downstream builds the entry and reads it
      // back out of a deny set, and neither should mean hardcoding `#` — the spelling is a wire
      // format, so the one place that knows it publishes it.
      'keyTarget',
      'keyFromTarget',
      'KEY_TARGET_PREFIX',
      'didFromInception',
      'DID_PREFIX',
      'encodeKey',
      'decodeKey',
      'tryDecodeKey',
      'verifyInception',
      'verifyRotate',
      'verifyReset',
      'verifySignatures',
      'foldLog',
      'keyStateAt',
      // Carrying a state forward without silently dropping part of it, and the reasons a
      // snapshot is refused with.
      'snapshotOf',
      'isMemberEntry',
      'ROTATE_NEEDS_SNAPSHOT',
      'SNAPSHOT_MALFORMED',
      'SNAPSHOT_MEMBER_KEY_IS_ROOT',
      'SNAPSHOT_MEMBER_DID_MISMATCH',
      'SNAPSHOT_DROPS_RETIRED_KEY',
      'resolveBranches',
      'enumerateProfiles',
      'handleForDID',
      'createControllerResolver',
      'createControllerIdentity',
    ]) {
      expect(controller).toHaveProperty(name)
    }
  })

  test('does not leak internal helpers', () => {
    expect(controller).not.toHaveProperty('signEvent')
  })

  test('does not export the capability-authorised revoke surface', () => {
    for (const name of [
      'foldLogAsync',
      'resolveBranchesAsync',
      'createControllerIdentityAsync',
      'createControllerIdentityWithKeyAsync',
      'createRevokeWithKey',
      'verifyEventSignedBy',
      // The chain revoke left the root chain with it.
      'createRevoke',
      'verifyRevoke',
      'pruneDenySet',
      'CAPABILITY_VERIFIER_FAILED',
      'CAPABILITY_VERIFIER_MALFORMED_ANSWER',
      'REVOKE_NOT_SIGNED_BY_AUDIENCE',
      'CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD',
      'CAPABILITY_REVOKE_NEEDS_VERIFIER',
    ]) {
      expect(controller).not.toHaveProperty(name)
    }
  })
})
