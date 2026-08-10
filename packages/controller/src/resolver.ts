import {
  type DIDMethodResolver,
  IssuerKeyNotFoundError,
  type ResolvedAgreementKey,
  type ResolvedSigningKey,
  type ResolveIssuerHeader,
} from '@kokuin/token'

import { DID_PREFIX, decodeKey, type SignedEvent } from './events.js'
import type { FoldOptions, KeyState } from './fold.js'
import { currentStateAsync } from './state.js'

const CONTEXT = 'Controller resolver'

/**
 * The `k` entry a token's `kid` names, or the first published key when it carries none.
 *
 * The format is `#<the multibase key exactly as it appears in `k`>` — a fragment whose body is the
 * key itself, matched against the folded key set by membership. An index-based fragment was
 * rejected for this: an index means whatever the key set said at the time, and a token outlives
 * the state that gave its `kid` meaning.
 *
 * A `kid` outside the current set is an error, never a fall back to `keys[0]`. Falling back would
 * check the signature against a key the token never claimed — and for the common case of a key the
 * log has since rotated away, "the signer named a retired key" is precisely the answer a verifier
 * must not paper over.
 *
 * The bare key without the leading `#` is rejected rather than accepted as a second spelling: the
 * fragment form is wire-visible and effectively permanent, so it has exactly one spelling.
 *
 * Both rejections are an `IssuerKeyNotFoundError`, not the plain error the rest of this file
 * throws: the DID *was* resolved and its log *did* fold — what failed is the key the token named.
 * The distinction is load-bearing, not cosmetic. `resolveIssuerWithDoc` retypes everything else a
 * method resolver throws as `UnresolvableIssuerError`, and `@kokuin/capability`'s revocation
 * checker denies a capability on that type; since `kid` is an unauthenticated header field, a
 * fabricated record naming this DID and any invented key would otherwise deny every capability
 * this controller ever issued.
 */
function selectSigningKey(did: string, keys: Array<string>, kid?: string): string {
  if (kid == null) {
    return keys[0]
  }
  if (!kid.startsWith('#')) {
    throw new IssuerKeyNotFoundError(`Controller ${did} kid is not a key fragment: ${kid}`)
  }
  const key = kid.slice(1)
  if (!keys.includes(key)) {
    throw new IssuerKeyNotFoundError(
      `Controller ${did} kid names a key outside the current set: ${kid}`,
    )
  }
  return key
}

export type ControllerResolverOptions = {
  /**
   * Load a controller's event log. Returns undefined when the DID is unknown.
   *
   * **Answer with the log up to the event being verified, not necessarily the whole log**, when a
   * `verifyCapability` is configured. A capability authorising a revoke is issued by the very
   * profile whose log carries that revoke, so verifying it resolves the issuer, which folds the
   * log, which reaches the same revoke, which verifies the capability again — without end. The
   * prefix is also the state the capability has to be checked against: a key set the log rotated
   * away afterwards must not verify a grant made under it. A same-DID cycle is caught and turned
   * into an error rather than a hang, but the error is a diagnosis, not a fix.
   */
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
  // DIDs whose state this instance is in the middle of computing. A capability-authorised revoke
  // sends the fold back through `verifyCapability`, which resolves the capability's issuer —
  // ordinarily this same profile — so a `loadLog` answering with the whole log re-enters `loadState`
  // for a DID already in flight and never returns. Left unguarded that is not a stack overflow but
  // an await-chained loop doing Ed25519 work forever, reachable from any DID string a peer hands to
  // `resolve`. Failing closed with the fix in the message is the only outcome a deployment can act
  // on. Per instance, and cleared in `finally`, so it constrains nothing else: two *different*
  // profiles vouching for each other still resolve, which is the shape a `did:kokuin:` audience
  // has. A cycle spanning two resolver instances is not caught — that would need the set to be
  // shared through the options.
  const inFlight = new Set<string>()

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
    if (inFlight.has(did)) {
      throw new Error(
        `${CONTEXT}: cyclic resolution of ${did} — loadLog must answer with the log prefix up to the event carrying the capability`,
      )
    }
    inFlight.add(did)
    try {
      const events = await options.loadLog(did)
      if (events == null || events.length === 0) {
        throw new Error(`Unknown DID: ${did}`)
      }
      return await currentStateAsync(did, events, CONTEXT, {
        verifyCapability: options.verifyCapability,
      })
    } finally {
      inFlight.delete(did)
    }
  }

  return {
    method: 'kokuin',
    async resolve(did: string, header: ResolveIssuerHeader = {}): Promise<ResolvedSigningKey> {
      const state = await loadState(did)
      if (state.keys.length === 0) {
        throw new Error(`Controller ${did} has no signing key`)
      }
      const key = decodeKey(selectSigningKey(did, state.keys, header.kid))
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
