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
      'createRevoke',
      'createRevokeWithKey',
      // A `rev` target may name a key instead of a DID. Downstream builds the target and reads it
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
      'verifyRevoke',
      'verifySignatures',
      'foldLog',
      'foldLogAsync',
      'keyStateAt',
      'resolveBranches',
      // The management tier's form: the sync one cannot verify a capability-authorised revoke, so
      // a log carrying one has no duplicity detection at all without this.
      'resolveBranchesAsync',
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
      // "This call was not equipped to check a capability" — the fold's answer to a `cap`-bearing
      // revoke, which a caller has to tell from a log that is actually broken.
      'CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD',
      'CAPABILITY_REVOKE_NEEDS_VERIFIER',
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
