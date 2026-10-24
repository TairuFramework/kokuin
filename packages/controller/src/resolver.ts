import type { DIDMethodResolver } from '@kokuin/token'

import type { EpochLimits } from './epoch.js'
import { DID_PREFIX } from './events.js'
import { memoizedAuthoritativeLog } from './fold-memo.js'
import type { LogStore } from './history.js'
import { type ControllerLog, isControllerLog } from './log.js'
import { type FoldedView, resolverOver } from './state-resolver.js'

const CONTEXT = 'Controller resolver'

export type ControllerResolverOptions = {
  /**
   * Load a controller's event log. Returns undefined when the DID is unknown.
   *
   * **Answer with the whole log**: the fold needs every chain event and every current-epoch event,
   * and a prefix resolves to a head that is missing whatever came after it — a withheld epoch revoke
   * is a denial this resolution does not see.
   *
   * Called on every resolution: the log is always re-read, so a revoke landing between two
   * resolutions takes effect. Reuse the instance rather than building one per resolution: concurrent
   * resolutions of one DID share a single in-flight fold, and that entry drops as soon as the fold
   * settles. The fold itself is memoized process-wide by the exact log (and, with a `history`, the
   * exact log seen), so re-reading an unchanged log does not verify its signatures again; any new
   * event changes the key and is folded.
   *
   * One re-entry hazard remains, not this callback's: a `verifyToken` hook that resolves *this* DID
   * through *this* resolver joins the calling fold and awaits a promise that cannot settle. Give such
   * a hook a resolver of its own.
   */
  loadLog(did: string): Promise<ControllerLog | undefined>
  /**
   * Where to remember the last log accepted for each DID, so a later one that is *behind* it is
   * refused rather than answered from. Without one, truncation is a silent revocation bypass: a peer
   * serving a prefix that stops just before the event denying their device produces a log that folds
   * cleanly and yields a deny set missing exactly that entry.
   *
   * Optional, because the guarantee needs storage this package cannot provide and a first encounter
   * has nothing to compare against. **Configure one if this process resolves the same DIDs more than
   * once.** See {@link LogStore}, and `createMemoryLogStore` for the process-lifetime version.
   */
  history?: LogStore
}

/**
 * A `did:kokuin:` resolver that can also hand out frozen views of itself.
 *
 * `frozen()` returns a resolver that loads and folds each DID at most once for its lifetime and
 * answers every member from that one fold. A verification asking several questions of one controller
 * — is the issuer a member, which key does it pin, until when, is any audience on the delegation
 * chain denied — must get them all from one state of the log: answered live, a revoke landing
 * between two of them gives a verdict no single state of the log supports (a member checked before
 * its removal, a denial checked after a settlement dropped it). Use one view per verification and
 * drop it after, since it never sees anything newer than its first fold.
 */
export type ControllerResolver = DIDMethodResolver & { frozen(): DIDMethodResolver }

/**
 * A `did:kokuin:` resolver for `@kokuin/token`. Injected rather than imported by token: this package
 * depends on token for signing, so the reverse import would cycle. Token resolves `iss` through the
 * interface without knowing the fold exists.
 *
 * Every member answers from the head (the chain's last state merged with the current epoch) except
 * `resolveHistoric`, which scans the chain's states for a rotated-away key. While the epoch is
 * saturated, every member refuses (see `resolverOver`).
 */
export function createControllerResolver(options: ControllerResolverOptions): ControllerResolver {
  return createControllerResolverWithin(options)
}

/**
 * {@link createControllerResolver} under lowered epoch limits. Test-only: saturation is then
 * reachable without thousands of signatures. Not exported from the package.
 */
export function createControllerResolverWithin(
  options: ControllerResolverOptions,
  limits?: Partial<EpochLimits>,
): ControllerResolver {
  // The fold currently under way for each DID, so overlapping resolutions of one DID share it (two
  // tokens from one issuer verified in parallel is ordinary — token caches only `did:peer:4`).
  //
  // Also the last line against a `loadLog` that re-enters resolution for the DID it is loading. The
  // fold no longer does that itself, but a caller's `loadLog` can still reach `resolve` for the same
  // DID: sharing the pending fold makes that a quiet deadlock the caller's request timeout catches,
  // rather than an await-chained Ed25519 loop that starves the timer queue.
  //
  // Not a cache of answers: removed as soon as the fold settles, so a later resolution re-reads the
  // log. Re-reading an unchanged log is cheap because the fold of those exact bytes is memoized (see
  // `memoizedAuthoritativeLog`), keyed by content, so a changed log is never answered from memory.
  const inFlight = new Map<string, Promise<FoldedView>>()

  // Shared by every member: load, fold, throw `Unknown DID` when absent. The chain's states as well
  // as the head, because `resolveHistoric` answers about rotated-away keys.
  async function computeView(did: string): Promise<FoldedView> {
    const log = await options.loadLog(did)
    if (log == null || (isControllerLog(log) && log.chain.length === 0)) {
      throw new Error(`Unknown DID: ${did}`)
    }
    // Without a store, the same fold against no memory: the request limit, the chain, then the
    // epoch — one path, so the two configurations cannot disagree about what a log means.
    if (options.history == null) {
      return memoizedAuthoritativeLog(
        { did, loaded: log, seen: undefined, context: CONTEXT },
        limits,
      ).result
    }
    // Compared against what this party last accepted, so a truncated log — folding cleanly, missing
    // the revoke that matters — is refused. See `LogStore`.
    // Inside the store's merge, so two resolutions of one DID never lose each other's events. A log
    // that lost throws out of the update, so nothing is written and the store never moves backwards.
    // The answer is the merged fold — what was seen plus what was loaded — not the presentation.
    // The merge and the comparison run on every resolution: the memo is keyed by the seen log as
    // well as the loaded one, so a prefix memoized before a longer log was accepted is a different
    // entry from that prefix presented against the longer log, and the latter is folded and refused.
    let view: FoldedView | undefined
    await options.history.merge(did, async (seen) => {
      const settled = memoizedAuthoritativeLog({ did, loaded: log, seen, context: CONTEXT }, limits)
      view = settled.result
      return settled.log
    })
    if (view === undefined) {
      throw new Error(`${CONTEXT}: the log store did not run the merge for ${did}`)
    }
    return view
  }

  async function loadView(did: string): Promise<FoldedView> {
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
    const fold = Promise.resolve().then(() => computeView(did))
    inFlight.set(did, fold)
    try {
      return await fold
    } finally {
      // Removal is what keeps this from being a cache of answers: the next resolution re-reads the
      // log, so a revoke landing between two resolutions takes effect (its new digest misses the fold
      // memo). In `finally`, so a rejected fold clears too.
      inFlight.delete(did)
    }
  }

  return {
    ...resolverOver(loadView),
    frozen(): DIDMethodResolver {
      // The promise, not the settled view: concurrent first calls for one DID join one load and
      // fold, rather than each starting its own and answering from whichever settled.
      const views = new Map<string, Promise<FoldedView>>()
      return resolverOver((did) => {
        const known = views.get(did)
        if (known !== undefined) {
          return known
        }
        const view = loadView(did)
        views.set(did, view)
        // A failed load is no answer to freeze: dropped, so a later call loads afresh. Every answer
        // this view gave for the DID came from that failure, so the next fold is still its first.
        view.catch(() => {
          if (views.get(did) === view) {
            views.delete(did)
          }
        })
        return view
      })
    },
  }
}
