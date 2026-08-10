import type { DIDString } from '@kokuin/token'

import { digestOf } from '../src/canonical.js'
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  didFromInception,
  encodeKey,
  type InceptionEvent,
  type SignedEvent,
  signEvent,
} from '../src/events.js'

/** The co-signer's seed. Not a controller seed anywhere else in the suite. */
const COSIGNER_SEED = new Uint8Array(32).fill(23)

export type TwoKeyLog = {
  did: DIDString
  log: Array<SignedEvent>
  inception: SignedEvent<InceptionEvent>
  /** `k[0]` — the co-signer's key, derived from a seed the controller does not hold. */
  cosignerKey: string
  /** `k[1]` — the key `seed` derives at the usual authority path. */
  controllerKey: string
}

/**
 * A one-event log whose inception publishes **two** authority keys.
 *
 * `createInception` and `createRotate` publish exactly one key in `k`, so a multi-key key set
 * cannot be produced through the generators — it has to be hand-built here. Nothing about the
 * result is faked: the DID is the digest of this very event, both signatures are made over its
 * canonical bytes, and `n` commits one next key per current key, so `verifyInception` and the fold
 * accept it exactly as they accept a generated inception.
 *
 * The controller's own key sits at index **1** on purpose. `keys[0]` belongs to a co-signer whose
 * private key the controller does not hold, so any code that silently reaches for `keys[0]` picks
 * a key this controller cannot sign with — which is what makes `kid` selection observable.
 */
export function buildTwoKeyLog(seed: Uint8Array, profile = 0): TwoKeyLog {
  const controller = deriveKeyPair(seed, authorityPath(profile, 0, 0), 'EdDSA')
  const controllerNext = deriveKeyPair(seed, authorityPath(profile, 0, 1), 'EdDSA')
  const cosigner = deriveKeyPair(COSIGNER_SEED, authorityPath(profile, 0, 0), 'EdDSA')
  const cosignerNext = deriveKeyPair(COSIGNER_SEED, authorityPath(profile, 0, 1), 'EdDSA')
  const agreement = deriveKeyPair(seed, agreementPath(profile, 0, 0), 'X25519')
  const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')

  const cosignerKey = encodeKey(cosigner.publicKey, 'EdDSA')
  const controllerKey = encodeKey(controller.publicKey, 'EdDSA')
  const event: InceptionEvent = {
    v: 1,
    t: 'icp',
    g: 0,
    s: 0,
    crit: true,
    k: [cosignerKey, controllerKey],
    ka: [encodeKey(agreement.publicKey, 'X25519')],
    n: [
      digestOf(encodeKey(cosignerNext.publicKey, 'EdDSA')),
      digestOf(encodeKey(controllerNext.publicKey, 'EdDSA')),
    ],
    kt: 2,
    nt: 2,
    r: digestOf(encodeKey(recovery.publicKey, 'EdDSA')),
  }
  // Positional against `k`, so the co-signer signs first.
  const inception: SignedEvent<InceptionEvent> = {
    event,
    sigs: signEvent(event, [cosigner.privateKey, controller.privateKey]),
  }

  return {
    did: didFromInception(event),
    log: [inception],
    inception,
    cosignerKey,
    controllerKey,
  }
}

/** A well-formed authority key that no log in this suite publishes. */
export function strangerKey(): string {
  return encodeKey(
    deriveKeyPair(new Uint8Array(32).fill(31), authorityPath(0, 0, 0), 'EdDSA').publicKey,
    'EdDSA',
  )
}
