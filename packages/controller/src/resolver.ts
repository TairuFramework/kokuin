import type {
  DIDMethodResolver,
  ResolvedAgreementKey,
  ResolvedSigningKey,
  ResolveIssuerHeader,
} from '@kokuin/token'

import { DID_PREFIX, type SignedEvent } from './events.js'
import type { FoldOptions, KeyState } from './fold.js'
import { authoritativeStates, type LogStore } from './history.js'
import { allStatesAsync } from './state.js'
import { agreementKeysFrom, DID_METHOD, signingKeyFrom } from './state-resolver.js'

const CONTEXT = 'Controller resolver'

export type ControllerResolverOptions = {
  /**
   * Load a controller's event log. Returns undefined when the DID is unknown.
   *
   * **Answer with the whole log**, even when a `verifyCapability` is configured. A capability
   * authorising a revoke must be checked at the position the fold is at — a rotated-away key set must
   * not verify a grant made under it, a device denied before that position must not author one —
   * and neither question can be answered from a DID alone, all this callback receives. So neither is
   * asked of it: the fold answers both by handing the verifier a resolver built from the prefix
   * states. See `FoldOptions.verifyCapability`.
   *
   * ```ts
   * const resolver = createControllerResolver({
   *   loadLog: async (did) => await store.log(did),
   *   verifyCapability: createControllerCapabilityVerifier(),
   * })
   * ```
   *
   * Reuse the instance rather than building one per resolution: concurrent resolutions of one DID
   * share a single in-flight fold. Not a cache — the entry drops as soon as the fold settles.
   *
   * One re-entry hazard remains, not this callback's: a `verifyToken` hook or a `resolver` passed to
   * the capability verifier that resolves *this* DID through *this* resolver joins the calling fold
   * and awaits a promise that cannot settle. Give such a hook a resolver of its own.
   */
  loadLog(did: string): Promise<Array<SignedEvent> | undefined>
  /**
   * Verify a capability authorising a non-authority signer to revoke, forwarded to the fold. Optional
   * because most logs carry none: without it a log containing one fails to fold rather than being
   * trusted. `createControllerCapabilityVerifier()` from `@kokuin/capability` is the implementation;
   * it needs a registry only for a chain delegate whose DID method is not resolvable from the
   * identifier alone.
   */
  verifyCapability?: FoldOptions['verifyCapability']
  /**
   * Where to remember the last log accepted for each DID, so a later one that is *behind* it is
   * refused rather than answered from. Without one, truncation is a silent revocation bypass: a peer
   * serving a prefix that stops just before the `rev` denying their device produces a log that folds
   * cleanly and yields a deny set missing exactly that entry.
   *
   * Optional, because the guarantee needs storage this package cannot provide and a first encounter
   * has nothing to compare against. **Configure one if this process resolves the same DIDs more than
   * once.** See {@link LogStore}, and `createMemoryLogStore` for the process-lifetime version.
   */
  history?: LogStore
}

/**
 * A `did:kokuin:` resolver for `@kokuin/token`. Injected rather than imported by token: this package
 * depends on token for signing, so the reverse import would cycle. Token resolves `iss` through the
 * interface without knowing the fold exists.
 */
export function createControllerResolver(options: ControllerResolverOptions): DIDMethodResolver {
  // The fold currently under way for each DID, so overlapping resolutions of one DID share it (two
  // tokens from one issuer verified in parallel is ordinary — token caches only `did:peer:4`).
  //
  // Also the last line against a `loadLog` that re-enters resolution for the DID it is loading. The
  // fold no longer does that itself, but a caller's `loadLog` can still reach `resolve` for the same
  // DID: sharing the pending fold makes that a quiet deadlock the caller's request timeout catches,
  // rather than an await-chained Ed25519 loop that starves the timer queue.
  //
  // Not a cache: removed as soon as the fold settles, so a later resolution re-folds.
  const inFlight = new Map<string, Promise<Array<KeyState>>>()

  // Shared by every member: load, fold, throw `Unknown DID` when absent. The whole state array
  // rather than the head, because `resolveHistoric` answers about rotated-away keys; head-only
  // members take `states[states.length - 1]`. Always the async fold: it differs from `foldLog` only
  // in awaiting a capability-authorised revoke's verifier, so a mode-selecting option would choose
  // nothing — the verifier is the only thing a caller supplies.
  async function computeStates(did: string): Promise<Array<KeyState>> {
    const events = await options.loadLog(did)
    if (events == null || events.length === 0) {
      throw new Error(`Unknown DID: ${did}`)
    }
    const foldOptions = { verifyCapability: options.verifyCapability }
    if (options.history == null) {
      return await allStatesAsync({ did, events, context: CONTEXT, options: foldOptions })
    }
    // Compared against what this party last accepted, so a truncated log — folding cleanly, missing
    // the revoke that matters — is refused. See `LogStore`.
    const seen = await options.history.get(did)
    const { log, states } = await authoritativeStates({
      did,
      loaded: events,
      seen,
      context: CONTEXT,
      options: foldOptions,
    })
    // Only after it has folded, and only in the memory-keeping direction: a log that lost never
    // reaches here, so the store never moves backwards.
    await options.history.set(did, log)
    return states
  }

  async function loadStates(did: string): Promise<Array<KeyState>> {
    if (!did.startsWith(DID_PREFIX)) {
      throw new Error(`Unknown DID: ${did}`)
    }
    const pending = inFlight.get(did)
    if (pending != null) {
      // Awaiting an existing fold, never clearing it — the call that created it owns removal, so a
      // joiner cannot evict an entry a third caller is about to join.
      return await pending
    }
    // Deferred by a microtask so the entry is registered *before* `loadLog` runs — otherwise a
    // `loadLog` that re-enters `resolve` before its own first `await` recurses to a stack overflow
    // while the map is still empty.
    const fold = Promise.resolve().then(() => computeStates(did))
    inFlight.set(did, fold)
    try {
      return await fold
    } finally {
      // Removal is what keeps this from being a cache: the next resolution re-reads and re-folds, so
      // a revoke landing between two resolutions takes effect. In `finally`, so a rejected fold
      // clears too.
      inFlight.delete(did)
    }
  }

  return {
    method: DID_METHOD,
    // The head's key set only: a profile that rotated away from a key answers "no" for it here, which
    // is what makes `rotate` retire a leaked authority key rather than add one beside it.
    async resolve(did: string, header: ResolveIssuerHeader = {}): Promise<ResolvedSigningKey> {
      return signingKeyFrom({ did, states: await loadStates(did), header })
    },
    // Every key set within the current generation, for a caller verifying past-issued material. A
    // `rotate` must not invalidate those; a `reset` still does, and the scan stops at the generation
    // boundary. See `signingKeyFrom` in `state-resolver.ts`.
    async resolveHistoric(
      did: string,
      header: ResolveIssuerHeader = {},
    ): Promise<ResolvedSigningKey> {
      return signingKeyFrom({ did, states: await loadStates(did), header, historic: true })
    },
    async resolveDenySet(did: string): Promise<ReadonlySet<string>> {
      // The head's set, deliberately, not the state at any position a capability names: `iat` is
      // author-supplied and backdatable, so anchoring to it would let a revoked holder pick a
      // position at which it was not yet denied. The set is position-dependent *within the fold*; the
      // question a verifier asks is "is this grant valid now". Both spellings ride in it (see
      // `KeyState.deny`); the key half is enforced by `signingKeyFrom`, and the two forms cannot
      // collide. `loadStates` throws `Unknown DID` rather than answering an empty (= "nobody
      // revoked") set.
      const states = await loadStates(did)
      const head = states[states.length - 1]
      if (head === undefined) {
        throw new Error(`Unknown DID: ${did}`)
      }
      return head.deny
    },
    async resolveAgreementKey(did: string): Promise<Array<ResolvedAgreementKey>> {
      // The head's set only, unlike `resolve`. A retired agreement key is a downgrade, not a grant
      // the profile already made: the recipient decrypts old ciphertexts by re-deriving from the
      // seed, never by resolution.
      return agreementKeysFrom(did, await loadStates(did))
    },
  }
}
