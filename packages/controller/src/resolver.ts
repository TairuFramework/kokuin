import type { DIDMethodResolver, ResolvedSigningKey } from '@kokuin/token'

import { DID_PREFIX, decodeKey, type SignedEvent } from './events.js'
import { foldLog } from './fold.js'

export type ControllerResolverOptions = {
  /** Load a controller's event log. Returns undefined when the DID is unknown. */
  loadLog(did: string): Promise<Array<SignedEvent> | undefined>
}

/**
 * A `did:kokuin:` resolver for `@kokuin/token`.
 *
 * Injected rather than imported by token: this package depends on token for signing, so the
 * reverse import would be a cycle. Token resolves `iss` through the interface without knowing
 * the fold exists.
 */
export function createControllerResolver(options: ControllerResolverOptions): DIDMethodResolver {
  return {
    method: 'kokuin',
    async resolve(did: string): Promise<ResolvedSigningKey> {
      if (!did.startsWith(DID_PREFIX)) {
        throw new Error(`Unknown DID: ${did}`)
      }
      const events = await options.loadLog(did)
      if (events == null || events.length === 0) {
        throw new Error(`Unknown DID: ${did}`)
      }
      const result = foldLog(did, events)
      if (!result.ok) {
        throw new Error(`Invalid controller log for ${did}: ${result.reason}`)
      }
      const state = result.states[result.states.length - 1]
      if (state.keys.length === 0) {
        throw new Error(`Controller ${did} has no signing key`)
      }
      return { alg: 'EdDSA', publicKey: decodeKey(state.keys[0]) }
    },
  }
}
