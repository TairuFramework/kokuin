import type {
  DIDMethodResolver,
  ResolvedAgreementKey,
  ResolvedSigningKey,
  ResolveIssuerHeader,
} from '@kokuin/token'

import { DID_PREFIX, type SignedEvent } from './events.js'
import type { FoldOptions, KeyState } from './fold.js'
import { allStatesAsync } from './state.js'
import { agreementKeysFrom, DID_METHOD, signingKeyFrom } from './state-resolver.js'

const CONTEXT = 'Controller resolver'

export type ControllerResolverOptions = {
  /**
   * Load a controller's event log. Returns undefined when the DID is unknown.
   *
   * **Answer with the whole log**, including when a `verifyCapability` is configured. A capability
   * authorising a revoke is issued by the very profile whose log carries that revoke, and the
   * position that capability has to be checked at is the one the fold is at — a key set the log
   * rotated away afterwards must not verify a grant made under it, and a device the log denied
   * before that position must not author one. Neither question can be answered from a DID alone,
   * which is all this callback receives, so neither is asked of it: the fold answers both itself,
   * by handing the verifier a resolver built from the states before the event being verified. See
   * `FoldOptions.verifyCapability`.
   *
   * ```ts
   * const resolver = createControllerResolver({
   *   loadLog: async (did) => await store.log(did),
   *   verifyCapability: createControllerCapabilityVerifier(),
   * })
   * ```
   *
   * Reuse the instance rather than building one per resolution: concurrent resolutions of one DID
   * share a single in-flight fold, so reuse is both correct and cheaper. It is not a cache — the
   * entry is dropped as soon as the fold settles, so a log that has grown since takes effect.
   */
  loadLog(did: string): Promise<Array<SignedEvent> | undefined>
  /**
   * Verify a capability authorising a non-authority signer to revoke, forwarded to the fold.
   *
   * Optional because most logs carry none: without it a log containing a capability-authorised
   * revoke fails to fold rather than being trusted, exactly as the sync fold would have it.
   *
   * `createControllerCapabilityVerifier()` from `@kokuin/capability` is the implementation. It
   * needs no registry of its own for the profile being folded — the fold supplies that — only for
   * a delegate in the chain whose own DID method cannot be resolved from the identifier alone.
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
  // The fold currently under way for each DID, so overlapping resolutions of one DID share it:
  // two tokens from one issuer verified in parallel is the ordinary shape, since `@kokuin/token`
  // caches only `did:peer:4`, and folding the same log twice is pure waste.
  //
  // It is also the last line against a `loadLog` that re-enters resolution for the DID it is
  // loading. The fold no longer does that — a capability-authorised revoke is verified against a
  // resolver the fold builds from its own prefix, never by resolving this DID again — but a
  // caller's `loadLog` can still reach `resolve` for the same DID on its own. Sharing the pending
  // fold makes that a quiet deadlock (one pending promise, one `loadLog` call, no CPU, timer queue
  // live, so the caller's own request timeout catches it) rather than an await-chained Ed25519
  // loop that starves the timer queue and no timeout can catch.
  //
  // Not a cache: the entry is removed as soon as the fold settles, so a later resolution re-folds
  // and never answers from stale state.
  const inFlight = new Map<string, Promise<Array<KeyState>>>()

  // Shared by every member: load the log, fold it, throw `Unknown DID` when absent. A second copy
  // of this sequence would drift.
  //
  // The whole state array rather than the head alone: `resolve` has to answer about keys the log
  // has since rotated away, since a token outlives the state that gave its `kid` meaning. The
  // members that want only the head take `states[states.length - 1]`.
  //
  // Always the async fold. Both members are already async, and `foldLogAsync` differs from
  // `foldLog` only in being able to await a capability-authorised revoke's verifier — every other
  // log folds identically through either — so a mode-selecting option would choose nothing. The
  // verifier itself is the only thing a caller has to supply.
  async function computeStates(did: string): Promise<Array<KeyState>> {
    const events = await options.loadLog(did)
    if (events == null || events.length === 0) {
      throw new Error(`Unknown DID: ${did}`)
    }
    return await allStatesAsync(did, events, CONTEXT, {
      verifyCapability: options.verifyCapability,
    })
  }

  async function loadStates(did: string): Promise<Array<KeyState>> {
    if (!did.startsWith(DID_PREFIX)) {
      throw new Error(`Unknown DID: ${did}`)
    }
    const pending = inFlight.get(did)
    if (pending != null) {
      // Awaiting an existing fold, never clearing it — the call that created it owns removal, so a
      // joiner cannot evict an entry a third caller is still about to join.
      return await pending
    }
    // Deferred by a microtask so the entry is registered *before* `loadLog` runs. Calling
    // `computeStates` first would leave a window in which a `loadLog` that re-enters `resolve`
    // before its own first `await` recurses synchronously to a stack overflow, since the map is
    // still empty when it looks.
    const fold = Promise.resolve().then(() => computeStates(did))
    inFlight.set(did, fold)
    try {
      return await fold
    } finally {
      // Removal is what keeps this from being a cache: the next resolution re-reads the log and
      // re-folds, so a log that has grown — a revoke landing between two resolutions — takes
      // effect. A permanent entry would serve a superseded deny set forever, which on this branch
      // means a revoked device continuing to verify. In `finally`, so a rejected fold clears too.
      inFlight.delete(did)
    }
  }

  return {
    method: DID_METHOD,
    async resolve(did: string, header: ResolveIssuerHeader = {}): Promise<ResolvedSigningKey> {
      return signingKeyFrom(did, await loadStates(did), header)
    },
    async resolveDenySet(did: string): Promise<ReadonlySet<string>> {
      // The head's set, deliberately, and not the state at any position a capability names: `iat`
      // is author-supplied and backdatable, so anchoring to it would let a revoked holder choose a
      // position at which it was not yet denied. The set is position-dependent *within the fold* —
      // which is what stops a later clearing from retroactively validating earlier actions — and
      // the question a verifier asks is "is this grant valid now".
      //
      // `loadStates` throws `Unknown DID` for a log this resolver cannot load, which is what keeps
      // the answer honest: an empty set would read as "nobody is revoked".
      const states = await loadStates(did)
      return states[states.length - 1].deny
    },
    async resolveAgreementKey(did: string): Promise<Array<ResolvedAgreementKey>> {
      // The head's set only, unlike `resolve`. These are the keys a *sender* encrypts to, and a
      // retired agreement key is a downgrade rather than a grant the profile already made: the
      // recipient decrypts old ciphertexts by re-deriving from the seed, never by resolution.
      return agreementKeysFrom(did, await loadStates(did))
    },
  }
}
