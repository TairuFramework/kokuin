import type { ConformanceSuite, ControllerImplementation } from '@kokuin/controller-conformance'
import { runControllerConformance } from '@kokuin/controller-conformance'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { enumerateProfiles } from '../src/profiles.js'
import { resolveBranches } from '../src/supersede.js'

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
  enumerateProfiles,
  digestOf,
}

// `@kokuin/controller`'s events use a closed `EventType` union ('icp' | 'rot' | 'rev'), while the
// suite's `ConformanceEvent` intentionally widens `t` to `string` so its criticality group can
// construct an event of an unknown type. That widening makes the real functions' parameters
// contravariantly incompatible with the suite's declared signatures — a genuine variance mismatch
// between a closed wire format and an open contract type, not a loosened contract — so it is
// bridged with a single cast here rather than by widening `@kokuin/controller`'s own types.
runControllerConformance(suite, implementation as unknown as ControllerImplementation)
