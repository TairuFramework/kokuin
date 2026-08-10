import { createSigningIdentityForDID, type SigningIdentity } from '@kokuin/token'

import { authorityPath, deriveKeyPair } from './derivation.js'
import { didFromInception, encodeKey, type InceptionEvent, type SignedEvent } from './events.js'
import { foldLog } from './fold.js'

/**
 * A signing identity for a `did:kokuin:` profile, whose `iss` is the profile DID.
 *
 * Takes the log rather than a caller-supplied position, and folds it here. A rotation exists
 * precisely to retire the previous key, so an API that accepted `{ gen, seq }` would leave
 * signing with a superseded key reachable — the only position this can sign at is the one the
 * log's current state establishes.
 *
 * The key derived is the one at `keyGen`/`keySeq`, not at `gen`/`seq`: a revoke advances the
 * sequence without establishing a key (Amendment A), so the last *event* position and the
 * position where the current keys were established diverge as soon as a log carries one. Deriving
 * at `gen`/`seq` would produce a key that was never in `k` — an unverifiable token, silently.
 *
 * @throws when the log does not fold, when it publishes no signing key, or when the derived key
 * is not the profile's current authority key (a wrong `seed` or `profile` for this log).
 */
export function createControllerIdentity(
  seed: Uint8Array,
  profile: number,
  log: Array<SignedEvent>,
): SigningIdentity {
  if (log.length === 0) {
    throw new Error('Controller identity: empty log')
  }
  const first = log[0] as SignedEvent<InceptionEvent>
  if (first.event.t !== 'icp') {
    throw new Error('Controller identity: first event must be an inception')
  }

  const did = didFromInception(first.event)
  const result = foldLog(did, log)
  if (!result.ok) {
    throw new Error(
      `Controller identity: invalid log for ${did}: ${result.reason} at event ${result.index}`,
    )
  }

  const state = result.states[result.states.length - 1]
  if (state.keys.length === 0) {
    // Mirrors the resolve side (`resolver.ts`): a controller publishing no signing key must not
    // yield an identity that signs with a retired one.
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
    throw new Error(
      `Controller identity: derived key does not match the current authority key of ${did}`,
    )
  }

  return createSigningIdentityForDID(did, privateKey)
}
