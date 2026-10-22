# Management tier follow-ons

**Origin:** `completed/2026-10-21-management-tier-on-log.complete.md`.

**Reviewed 2026-10-22** as release cleanup (`completed/2026-10-22-management-tier-follow-ons.complete.md`).
The smaller gaps were settled there. What is left here stays deliberately, each item with the
trigger that should reopen it.

## 1. A `LogStore` is trusted for signatures (medium)

`authoritativeLog` does not re-verify the current epoch's stored events. It only re-authorises them.
So a raw write to the store can plant a forged event that is then applied: a member added, not
merely an event forgotten. A reviewer confirmed this with a script that wrote a forged `add`
through `store.merge` and saw `resolveMember` return it, where the same log presented without a
store was refused.

Today this is enforced by documentation only (`history.ts`, `controller.md`, `security.md`, and the
store-controller `api.ts` and README): write only `authoritativeLog` output. Options, if that is not
enough:

- an opt-in `verifyHeld` flag that re-verifies once per process and caches the result per digest
  and signature list;
- a provenance mark on stored rows (needs a local MAC key: bytes alone cannot carry an unforgeable
  mark);
- re-verifying on load only when the stored row was written by a different code path.

Reverting to re-verify every time costs about 4 s per resolution of a held 4000-event epoch.

**Kept as documented trust.** No writer outside `authoritativeLog` exists today, and every option
costs re-verification or a MAC key that nothing needs yet. Reopen when a sync or replication path
writes peer bytes into a `LogStore`.

## 2. Held re-resolution still grows with the epoch (low)

A held 4000-event epoch re-resolves in about 0.57 s with nothing new. The cost is the causal parent
joins and the denial matcher, both linear-or-worse in epoch size. Measured worst shape: joins about
1.4 s. Candidates are an incremental fold over held state, or caching the folded `after` states per
digest.

**Deferred.** The cost appears only near the `MAX_EPOCH_EVENTS` ceiling, which in practice means a
flood that root then settles. Reopen if a real deployment holds large epochs between settlements.

## 3. A held event keeps its first valid signature copy (low)

When copies of one event carry different valid signature lists (multi-key root events only), each
verifier keeps whichever it stored first. Two verifiers may hold different bytes for one event. The
folded head is the same. This is documented on `FoldEpochParams.trusted`. Decide whether convergence
of stored bytes matters, for example for log hashing across peers.

**Kept.** Nothing hashes stored bytes across peers. Converging would mean verifying a second copy
of a held event, which the failed-signature budget deliberately skips. Reopen if anything starts
comparing stored logs byte for byte.
