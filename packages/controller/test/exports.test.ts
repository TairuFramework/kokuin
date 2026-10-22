import { describe, expect, expectTypeOf, test } from 'vitest'

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
      // The management tier's events: builders, the shape guard, the signature check, the limits.
      'createAdd',
      'createRenew',
      'createRemove',
      'createRevoke',
      'isEpochEventShape',
      'verifyEpochSignature',
      'MAX_EPOCH_EVENTS',
      'MAX_LOG_EVENTS',
      'MAX_EVENT_PARENTS',
      'MAX_EVENT_BYTES',
      'MAX_EVENT_SIGNATURES',
      // A presentation refused for the signatures it makes a verifier check in vain.
      'MAX_FAILED_SIGNATURES',
      'TOO_MANY_FAILED_SIGNATURES',
      'DEFAULT_LEASE_SECONDS',
      'resolveBranches',
      // Remembering what was seen, and combining or trimming logs: what a consumer persisting
      // controller logs builds its store on.
      'authoritativeLog',
      'createMemoryLogStore',
      'mergeLogs',
      'pruneLog',
      'epochHeads',
      'LOG_FORKED',
      'LOG_NOT_AUTHORITATIVE',
      'LOG_UNFOLDABLE',
      'enumerateProfiles',
      'handleForDID',
      'createControllerResolver',
      // What resolution refuses with when the epoch is saturated or a member is not live.
      'EPOCH_SATURATED',
      'MEMBER_NOT_EFFECTIVE',
      'createControllerIdentity',
    ]) {
      expect(controller).toHaveProperty(name)
    }
  })

  test('exports the types authoritativeLog is written in', () => {
    // Type-level: a consumer wrapping `authoritativeLog` in its own store names these.
    expectTypeOf(controller.authoritativeLog)
      .parameter(0)
      .toEqualTypeOf<controller.AuthoritativeLogParams>()
    expectTypeOf(controller.authoritativeLog).returns.toEqualTypeOf<controller.AuthoritativeLog>()
  })

  test('does not leak internal helpers', () => {
    expect(controller).not.toHaveProperty('signEvent')
    // Lowers the saturation threshold: a test seam, never a production knob.
    expect(controller).not.toHaveProperty('createControllerResolverWithin')
  })

  test('does not export the capability-authorised revoke surface', () => {
    for (const name of [
      'foldLogAsync',
      'resolveBranchesAsync',
      'createControllerIdentityAsync',
      'createControllerIdentityWithKeyAsync',
      'createRevokeWithKey',
      'verifyEventSignedBy',
      // The chain revoke left the root chain with it; the epoch `createRevoke` is another function.
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
