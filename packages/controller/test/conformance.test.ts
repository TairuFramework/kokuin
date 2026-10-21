import type {
  ConformanceEpochBody,
  ConformanceSuite,
  ControllerImplementation,
} from '@kokuin/controller-conformance'
import { runControllerConformance } from '@kokuin/controller-conformance'
import { type DIDDoc, encodePeer4 } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  createAdd,
  createRemove,
  createRenew,
  createRevoke,
  type EpochSigner,
} from '../src/epoch-events.js'
import {
  type CreateRotateOptions,
  createInception,
  createReset,
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
import { foldLog, type KeyState } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'
import { enumerateProfiles } from '../src/profiles.js'
import { resolveBranches } from '../src/supersede.js'

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

/** Test-support only: a fresh Ed25519 member key pair and the `did:key` that carries it. */
function memberKeyPair(): { privateKey: Uint8Array; key: string; did: string } {
  const privateKey = ed25519.utils.randomSecretKey()
  const key = encodeKey(ed25519.getPublicKey(privateKey), 'EdDSA')
  return { privateKey, key, did: `did:key:${key}` }
}

/** Test-support only: a long-form `did:peer:4` carrying exactly `key` as its one signing key. */
function memberPeerDID(key: string): string {
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase: key }],
    authentication: ['#key-0'],
  } as DIDDoc
  return encodePeer4(doc).longForm
}

/** The one builder the contract names, over the real per-type ones. */
function createEpochEvent({
  signer,
  did,
  head,
  parents,
  body,
}: {
  signer: EpochSigner
  did: string
  head: KeyState
  parents: Array<string>
  body: ConformanceEpochBody
}) {
  const base = { did, head, parents }
  switch (body.t) {
    case 'add':
      if (!('root' in signer)) {
        throw new Error('an add is root-only')
      }
      return createAdd({ ...base, ...signer.root, member: body.member })
    case 'ren':
      return createRenew({ ...base, signer, add: body.add, lease: body.lease })
    case 'rmv':
      return createRemove({ ...base, signer, add: body.add })
    case 'rev':
      return createRevoke({ ...base, signer, target: body.target })
  }
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

// The conformance contract stays positional; the real `createRotate` takes a params object, so it
// is bridged here. `createReset`/`createInception` are positional already and pass through.
const implementation = {
  name: '@kokuin/controller',
  createInception,
  createRotate: (
    seed: Uint8Array,
    profile: number,
    did: string,
    prior: EventCommon,
    options: CreateRotateOptions,
  ) => createRotate({ seed, profile, did, prior, options }),
  createReset,
  didFromInception,
  foldLog,
  resolveBranches,
  enumerateProfiles,
  digestOf,
  recoveryPrivateKey,
  authorityPrivateKey,
  createEpochEvent,
  memberKeyPair,
  memberPeerDID,
  signEvent,
}

// `@kokuin/controller`'s events use a closed `EventType` union ('icp' | 'rot'), while the
// suite's `ConformanceEvent` intentionally widens `t` to `string` so its criticality group can
// construct an event of an unknown type. That widening makes the real functions' parameters
// contravariantly incompatible with the suite's declared signatures — a genuine variance mismatch
// between a closed wire format and an open contract type, not a loosened contract — so it is
// bridged with a single cast here rather than by widening `@kokuin/controller`'s own types.
runControllerConformance(suite, implementation as unknown as ControllerImplementation)
