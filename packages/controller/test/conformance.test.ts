import type { ConformanceSuite, ControllerImplementation } from '@kokuin/controller-conformance'
import { runControllerConformance } from '@kokuin/controller-conformance'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
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

const implementation = {
  name: '@kokuin/controller',
  createInception,
  createRotate,
  createReset,
  createRevoke,
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
