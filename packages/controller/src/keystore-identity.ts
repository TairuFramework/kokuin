import type { CryptoOptions, FullIdentity, KeyEntry } from '@kokuin/token'

import { createInception, didFor } from './events.js'
import type { LogStore } from './history.js'
import { createControllerIdentity } from './identity.js'

export type ProvideControllerIdentityParams = CryptoOptions & {
  /** The seed source: `provideAsync()`'s bytes are the controller root seed. Generates on first use. */
  entry: KeyEntry<Uint8Array>
  /** Which profile under the seed to resolve. */
  profile: number
  /** Where the last accepted log for the DID lives — loaded to restore, written to on first generate. */
  logStore: LogStore
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
  crypto,
}: ProvideControllerIdentityParams): Promise<FullIdentity> {
  const seed = (await entry.provideAsync()).slice()
  const did = didFor({ seed, profile })
  let log = await logStore.get(did)
  if (log == null || log.chain.length === 0) {
    const inception = [await createInception({ seed, profile, crypto })]
    // Through the merge, so a log another writer stored meanwhile is kept rather than overwritten.
    log = await logStore.merge({
      did,
      update: async (current) => {
        return current != null && current.chain.length > 0
          ? current
          : { chain: inception, events: [] }
      },
    })
  }
  return await createControllerIdentity({ seed, profile, log, crypto })
}
