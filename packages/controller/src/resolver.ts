import {
  type DIDMethodResolver,
  IssuerKeyNotFoundError,
  type ResolvedAgreementKey,
  type ResolvedSigningKey,
  type ResolveIssuerHeader,
} from '@kokuin/token'

import { DID_PREFIX, decodeKey, type SignedEvent } from './events.js'
import type { FoldOptions, KeyState } from './fold.js'
import { allStatesAsync } from './state.js'

const CONTEXT = 'Controller resolver'

/**
 * The key a token's `kid` names, or the head's first published key when it carries none.
 *
 * The format is `#<the multibase key exactly as it appears in `k`>` — a fragment whose body is the
 * key itself, matched against the folded key sets by membership. An index-based fragment was
 * rejected for this: an index means whatever the key set said at the time, and a token outlives
 * the state that gave its `kid` meaning.
 *
 * **Any key that was authoritative at some position within the current generation resolves**, not
 * only the head's. Answering from the head alone made a routine `rotate` invalidate every token,
 * capability and revocation record the profile had ever issued — including ones held by third
 * parties who cannot know a rotation happened. The spec reserves that blast radius for `reset`
 * ("discards everything under the prior generation, including every capability minted there") and
 * its remedy ladder — a cold rotate, with reset as the backstop — only means something if the two
 * differ. So a generation bump is the thing that invalidates, and the scan stops dead at the first
 * state from an earlier generation rather than continuing through it.
 *
 * Everything else stays as it was. A `kid` naming a key this profile never published, and one from
 * a superseded generation, are errors — never a fall back to `keys[0]`, which would check the
 * signature against a key the token never claimed. A `kid` absent still resolves to the head's
 * first key: accepting an earlier key when a token *names* it is not the same as volunteering one
 * when it names nothing, and `resolve` can only answer with one key.
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
function selectSigningKey(did: string, states: Array<KeyState>, kid?: string): string {
  const head = states[states.length - 1]
  if (kid == null) {
    return head.keys[0]
  }
  if (!kid.startsWith('#')) {
    throw new IssuerKeyNotFoundError(`Controller ${did} kid is not a key fragment: ${kid}`)
  }
  const key = kid.slice(1)
  // Backwards from the head, because the head's own key set is the overwhelmingly common answer.
  // `gen` never decreases across the fold, so the first state from another generation ends the
  // search — everything before it is superseded material, and reaching into it would undo the one
  // thing `reset` is for.
  for (let i = states.length - 1; i >= 0 && states[i].gen === head.gen; i--) {
    if (states[i].keys.includes(key)) {
      return key
    }
  }
  throw new IssuerKeyNotFoundError(
    `Controller ${did} kid names a key outside the current generation: ${kid}`,
  )
}

export type ControllerResolverOptions = {
  /**
   * Load a controller's event log. Returns undefined when the DID is unknown.
   *
   * **Answer with the log up to the event being verified, not necessarily the whole log**, when a
   * `verifyCapability` is configured. A capability authorising a revoke is issued by the very
   * profile whose log carries that revoke, so verifying it resolves the issuer, which folds the
   * log, which reaches the same revoke, which verifies the capability again. The prefix is also
   * the state the capability has to be checked against: a key set the log rotated away afterwards
   * must not verify a grant made under it.
   *
   * Answering with the whole log instead **deadlocks that DID's resolution**, and nothing here can
   * diagnose it: the in-flight resolution ends up awaiting itself, which is indistinguishable from
   * awaiting an independent resolution already under way, because nothing carries chain identity
   * across the callback. It is a quiet deadlock — one pending promise, one `loadLog` call, no CPU,
   * other DIDs on the same instance unaffected — so a caller-side timeout ends the waiting. Only
   * the caller knows how long its own `loadLog` may legitimately take, so that timeout belongs
   * there and not here.
   *
   * It ends the *call*, not the wedge. The unsettleable fold stays in flight, so every later
   * resolution of that DID on that instance joins it and waits forever too, without calling
   * `loadLog` again. **A wedged instance is finished for that DID**: fix `loadLog` and build a new
   * resolver. Evicting the entry on a timer was considered and rejected — it would put a timeout
   * back inside this file, where the legitimate duration of `loadLog` is unknown, and make correct
   * slow resolutions fail intermittently.
   *
   * **Reuse one resolver instance** rather than minting one per resolution or per hop. Concurrent
   * resolutions of one DID share a single in-flight fold, so reuse is both correct and cheaper;
   * a fresh instance at every hop shares nothing and turns the deadlock above into an unbounded
   * Ed25519 loop that starves the timer queue, which no timeout can catch.
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
  // The fold currently under way for each DID, so overlapping resolutions of one DID share it.
  //
  // Two problems meet here. A capability-authorised revoke sends the fold back out through
  // `verifyCapability`, which resolves the capability's issuer — ordinarily this same profile — so
  // a `loadLog` answering with the whole log re-enters `loadStates` for a DID already being folded.
  // Unguarded that is not a stack overflow but an await-chained Ed25519 loop that never returns and
  // starves the timer queue, so no host-side timeout can catch it. Meanwhile two *independent*
  // resolutions of one DID — two tokens from one issuer verified in parallel, the ordinary shape,
  // since `@kokuin/token` caches only `did:peer:4` — must both succeed.
  //
  // Nothing distinguishes those two cases: chain identity would have to cross both
  // `verifyCapability` and `@kokuin/token`'s `DIDMethodResolver.resolve`, a three-package change,
  // and `AsyncLocalStorage` is node-only while this package ships to browsers and Expo. So do not
  // try to tell them apart — make the shared answer correct for the honest case and harmless for
  // the other. Independent concurrent resolutions get one fold instead of two, which is both
  // correct and cheaper; self-re-entry awaits a promise that cannot settle, which is a deadlock
  // rather than an error, but a *quiet* one: one pending promise, one `loadLog` call, no CPU, and
  // the timer queue still live, so the caller's own request timeout catches it. Rejecting instead
  // would mean refusing the honest case as well — the round-2 shape, which is a guaranteed failure
  // in this feature's own target configuration.
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
    method: 'kokuin',
    async resolve(did: string, header: ResolveIssuerHeader = {}): Promise<ResolvedSigningKey> {
      const states = await loadStates(did)
      if (states[states.length - 1].keys.length === 0) {
        throw new Error(`Controller ${did} has no signing key`)
      }
      const key = decodeKey(selectSigningKey(did, states, header.kid))
      if (key.alg === 'X25519') {
        throw new Error(`Controller ${did} signing key is not a signature algorithm: ${key.alg}`)
      }
      return { alg: key.alg, publicKey: key.publicKey }
    },
    async resolveAgreementKey(did: string): Promise<Array<ResolvedAgreementKey>> {
      // The head's set only, unlike `resolve`. These are the keys a *sender* encrypts to, and a
      // retired agreement key is a downgrade rather than a grant the profile already made: the
      // recipient decrypts old ciphertexts by re-deriving from the seed, never by resolution.
      const states = await loadStates(did)
      return states[states.length - 1].agreement.map((value) => {
        const key = decodeKey(value)
        if (key.alg !== 'X25519') {
          throw new Error(`Controller ${did} publishes an unsupported agreement key: ${key.alg}`)
        }
        return { alg: key.alg, publicKey: key.publicKey }
      })
    },
  }
}
