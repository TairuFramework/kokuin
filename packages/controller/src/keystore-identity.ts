import type { FullIdentity, KeyEntry } from '@kokuin/token'

import { createInception, didFromInception } from './events.js'
import type { FoldOptions } from './fold.js'
import type { LogStore } from './history.js'
import { createControllerIdentityAsync } from './identity.js'

export type ProvideControllerIdentityParams = {
  /** The seed source: `provideAsync()`'s bytes are the controller root seed. Generates on first use. */
  entry: KeyEntry<Uint8Array>
  /** Which profile under the seed to resolve. */
  profile: number
  /** Where the last accepted log for the DID lives — loaded to restore, written to on first generate. */
  logStore: LogStore
  /** Forwarded to the fold for a log whose revoke carries a capability only the async fold can verify. */
  options?: FoldOptions
}

/**
 * Resolve a `did:kokuin:` {@link FullIdentity} from a keystore entry and a log store.
 *
 * Generate and restore in one call: the entry yields the seed (a fresh one on first use, the stored
 * one after), and the log store yields the event log (bootstrapping the inception when the DID has no
 * log yet). The DID is a pure function of `(seed, profile)`, so the same entry and profile always
 * resolve the same identity. A `KeyStore` caller passes `keyStore.entry(keyID)` as `entry`.
 */
export async function provideControllerIdentity({
  entry,
  profile,
  logStore,
  options,
}: ProvideControllerIdentityParams): Promise<FullIdentity> {
  const seed = await entry.provideAsync()
  const inception = createInception(seed, profile)
  const did = didFromInception(inception.event)
  let log = await logStore.get(did)
  if (log == null) {
    log = [inception]
    await logStore.set(did, log)
  }
  return createControllerIdentityAsync({ seed, profile, log, options })
}
