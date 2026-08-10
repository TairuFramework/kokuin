import type { DIDMethodResolver, ResolvedAgreementKey, ResolvedSigningKey } from '@kokuin/token'

import { DID_PREFIX, decodeKey, type SignedEvent } from './events.js'
import type { FoldOptions, KeyState } from './fold.js'
import { currentStateAsync } from './state.js'

const CONTEXT = 'Controller resolver'

export type ControllerResolverOptions = {
  /** Load a controller's event log. Returns undefined when the DID is unknown. */
  loadLog(did: string): Promise<Array<SignedEvent> | undefined>
  /**
   * Verify a capability authorising a non-authority signer to revoke, forwarded to the fold.
   *
   * Optional because most logs carry none: without it a log containing a capability-authorised
   * revoke fails to fold rather than being trusted, exactly as the sync fold would have it.
   */
  verifyCapability?: FoldOptions['verifyCapability']
}

/**
 * A `did:kokuin:` resolver for `@kokuin/token`.
 *
 * Injected rather than imported by token: this package depends on token for signing, so the
 * reverse import would be a cycle. Token resolves `iss` through the interface without knowing
 * the fold exists.
 */
export function createControllerResolver(options: ControllerResolverOptions): DIDMethodResolver {
  // Shared by both members: load the log, fold it, take the last state, throw `Unknown DID` when
  // absent. A second copy of this sequence would drift.
  //
  // Always the async fold. Both members are already async, and `foldLogAsync` differs from
  // `foldLog` only in being able to await a capability-authorised revoke's verifier — every other
  // log folds identically through either — so a mode-selecting option would choose nothing. The
  // verifier itself is the only thing a caller has to supply.
  async function loadState(did: string): Promise<KeyState> {
    if (!did.startsWith(DID_PREFIX)) {
      throw new Error(`Unknown DID: ${did}`)
    }
    const events = await options.loadLog(did)
    if (events == null || events.length === 0) {
      throw new Error(`Unknown DID: ${did}`)
    }
    return currentStateAsync(did, events, CONTEXT, { verifyCapability: options.verifyCapability })
  }

  return {
    method: 'kokuin',
    async resolve(did: string): Promise<ResolvedSigningKey> {
      const state = await loadState(did)
      if (state.keys.length === 0) {
        throw new Error(`Controller ${did} has no signing key`)
      }
      const key = decodeKey(state.keys[0])
      if (key.alg === 'X25519') {
        throw new Error(`Controller ${did} signing key is not a signature algorithm: ${key.alg}`)
      }
      return { alg: key.alg, publicKey: key.publicKey }
    },
    async resolveAgreementKey(did: string): Promise<Array<ResolvedAgreementKey>> {
      const state = await loadState(did)
      return state.agreement.map((value) => {
        const key = decodeKey(value)
        if (key.alg !== 'X25519') {
          throw new Error(`Controller ${did} publishes an unsupported agreement key: ${key.alg}`)
        }
        return { alg: key.alg, publicKey: key.publicKey }
      })
    },
  }
}
