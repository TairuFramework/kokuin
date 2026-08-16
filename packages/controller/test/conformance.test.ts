import type { ConformanceSuite, ControllerImplementation } from '@kokuin/controller-conformance'
import { runControllerConformance } from '@kokuin/controller-conformance'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  type CreateRotateOptions,
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  type EventCommon,
  // `signEvent` stays unexported from the package's public barrel (`src/index.ts`) — it is an
  // internal signing primitive, not part of the wire protocol. Importing it directly from
  // `events.js` here is legitimate: this is a test file, not a consumer of the public API, and
  // the conformance suite's root-override group needs to sign with an arbitrary (uncommitted)
  // key to isolate the recovery-digest check from signature verification.
  signEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { enumerateProfiles } from '../src/profiles.js'
import { resolveBranches, resolveBranchesAsync } from '../src/supersede.js'

/** Test-support only: the recovery private key `createReset` derives internally. */
function recoveryPrivateKey(seed: Uint8Array, profile: number): Uint8Array {
  return deriveKeyPair(seed, recoveryPath(profile), 'EdDSA').privateKey
}

/** Test-support only: the authority (signing) private key `createInception`/`createRotate` derive internally. */
function authorityPrivateKey(
  seed: Uint8Array,
  profile: number,
  gen: number,
  seq: number,
): Uint8Array {
  return deriveKeyPair(seed, authorityPath(profile, gen, seq), 'EdDSA').privateKey
}

/** Test-support only: the public half, which is what a capability pins as its audience key. */
function authorityPublicKey(
  seed: Uint8Array,
  profile: number,
  gen: number,
  seq: number,
): Uint8Array {
  return deriveKeyPair(seed, authorityPath(profile, gen, seq), 'EdDSA').publicKey
}

// vitest's `expect` is structurally wider than the suite's minimal `ConformanceExpectation` —
// every matcher the suite calls is present, so this single documented cast is safe. Keeping it
// here, at the call site, is what lets the suite's own types stay honest rather than widened to
// `any` to accommodate every runner.
const suite: ConformanceSuite = {
  describe,
  expect: expect as unknown as ConformanceSuite['expect'],
  test,
}

// The conformance contract stays positional; the real functions now take a params object, so the
// two that changed are bridged here. `createReset`/`createInception` are unchanged and pass through.
const implementation = {
  name: '@kokuin/controller',
  createInception,
  createRotate: (
    seed: Uint8Array,
    profile: number,
    did: string,
    prior: EventCommon,
    options?: CreateRotateOptions,
  ) => createRotate({ seed, profile, did, prior, options }),
  createReset,
  createRevoke: (
    seed: Uint8Array,
    profile: number,
    did: string,
    prior: EventCommon,
    target: string,
    keyPosition: { gen: number; seq: number },
    options?: { cap?: string },
  ) => createRevoke({ seed, profile, did, prior, target, keyPosition, cap: options?.cap }),
  didFromInception,
  foldLog,
  resolveBranches,
  resolveBranchesAsync,
  enumerateProfiles,
  digestOf,
  recoveryPrivateKey,
  authorityPrivateKey,
  authorityPublicKey,
  signEvent,
}

// `@kokuin/controller`'s events use a closed `EventType` union ('icp' | 'rot' | 'rev'), while the
// suite's `ConformanceEvent` intentionally widens `t` to `string` so its criticality group can
// construct an event of an unknown type. That widening makes the real functions' parameters
// contravariantly incompatible with the suite's declared signatures — a genuine variance mismatch
// between a closed wire format and an open contract type, not a loosened contract — so it is
// bridged with a single cast here rather than by widening `@kokuin/controller`'s own types.
runControllerConformance(suite, implementation as unknown as ControllerImplementation)
