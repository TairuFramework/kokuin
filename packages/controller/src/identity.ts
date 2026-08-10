import { createSigningIdentityForDID, type DIDString, type SigningIdentity } from '@kokuin/token'

import { authorityPath, deriveKeyPair } from './derivation.js'
import { didFromInception, encodeKey, type InceptionEvent, type SignedEvent } from './events.js'
import type { FoldOptions, KeyState } from './fold.js'
import { currentState, currentStateAsync } from './state.js'

const CONTEXT = 'Controller identity'

/**
 * The DID the log claims to be, read from its inception before any fold runs — the fold needs the
 * DID to check the inception against, so it cannot be the thing that produces it.
 */
function didFromLog(log: Array<SignedEvent>): DIDString {
  if (log.length === 0) {
    throw new Error(`${CONTEXT}: empty log`)
  }
  const first = log[0] as SignedEvent<InceptionEvent>
  if (first.event.t !== 'icp') {
    throw new Error(`${CONTEXT}: first event must be an inception`)
  }
  return didFromInception(first.event)
}

/**
 * Derive the signing key the folded state establishes and bind it to the DID. Shared by the sync
 * and async entry points, which differ only in how they reach the state.
 */
function identityForState(
  seed: Uint8Array,
  profile: number,
  did: DIDString,
  state: KeyState,
): SigningIdentity {
  if (state.keys.length === 0) {
    // Defensive, and unreachable through either fold today: `verifySignatures` rejects an empty
    // key set on every event that can establish one, and `rev` carries `keys` forward. Kept so
    // that a future event type that can empty the set fails here rather than deriving a key for a
    // controller that publishes none. `resolver.ts` holds the same guard for the same reason.
    throw new Error(`Controller ${did} has no signing key`)
  }

  const { privateKey, publicKey } = deriveKeyPair(
    seed,
    authorityPath(profile, state.keyGen, state.keySeq),
    'EdDSA',
  )
  // The resolver answers with `keys[0]`, so anything else here signs tokens nothing can verify.
  // Fail loudly at construction instead — the mismatch means the seed or profile is not this
  // log's.
  if (encodeKey(publicKey, 'EdDSA') !== state.keys[0]) {
    throw new Error(`${CONTEXT}: derived key does not match the current authority key of ${did}`)
  }

  return createSigningIdentityForDID(did, privateKey)
}

/**
 * A signing identity for a `did:kokuin:` profile, whose `iss` is the profile DID.
 *
 * Takes the log rather than a caller-supplied position, and folds it here, so the signing key is
 * always the one that log's current state establishes and never one the caller named. That is a
 * narrower guarantee than "cannot sign with a superseded key": the log is the caller's freshness
 * contract, and an identity built from a stale or truncated log signs with a key later events
 * retired, minting tokens a current verifier rejects. Rebuild the identity from a re-read log
 * after a rotation rather than holding one across it.
 *
 * The key derived is the one at `keyGen`/`keySeq`, not at `gen`/`seq`: a revoke advances the
 * sequence without establishing a key (Amendment A), so the last *event* position and the
 * position where the current keys were established diverge as soon as a log carries one. Deriving
 * at `gen`/`seq` would produce a key that was never in `k` — an unverifiable token, silently.
 *
 * Synchronous, and stays so: kubun's apply path depends on it. A log whose revoke carries a
 * capability cannot fold without awaiting a verifier, so it throws here — use
 * {@link createControllerIdentityAsync} for one.
 *
 * @throws when the log does not fold, or when the derived key is not the profile's current
 * authority key (a wrong `seed` or `profile` for this log).
 */
export function createControllerIdentity(
  seed: Uint8Array,
  profile: number,
  log: Array<SignedEvent>,
): SigningIdentity {
  const did = didFromLog(log)
  return identityForState(seed, profile, did, currentState(did, log, CONTEXT))
}

/**
 * Async sibling of {@link createControllerIdentity} for a log whose revoke carries a capability
 * authorising a non-authority signer, which only `foldLogAsync` can check.
 *
 * Identical in every other respect — same guards, same key derivation, same failures — so a log
 * without such a revoke resolves to the same identity through either entry point.
 *
 * @param options forwarded to the async fold; `verifyCapability` is what a capability-authorised
 * revoke needs, and without it such a log still fails to fold rather than being trusted.
 */
export async function createControllerIdentityAsync(
  seed: Uint8Array,
  profile: number,
  log: Array<SignedEvent>,
  options?: FoldOptions,
): Promise<SigningIdentity> {
  const did = didFromLog(log)
  return identityForState(seed, profile, did, await currentStateAsync(did, log, CONTEXT, options))
}
