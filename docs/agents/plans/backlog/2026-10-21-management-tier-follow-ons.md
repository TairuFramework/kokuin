# Management tier follow-ons

**Origin:** `completed/2026-10-21-management-tier-on-log.complete.md`.

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

## 2. Held re-resolution still grows with the epoch (low)

A held 4000-event epoch re-resolves in about 0.57 s with nothing new. The cost is the causal parent
joins and the denial matcher, both linear-or-worse in epoch size. Measured worst shape: joins about
1.4 s. Candidates are an incremental fold over held state, or caching the folded `after` states per
digest.

## 3. A held event keeps its first valid signature copy (low)

When copies of one event carry different valid signature lists (multi-key root events only), each
verifier keeps whichever it stored first. Two verifiers may hold different bytes for one event. The
folded head is the same. This is documented on `FoldEpochParams.trusted`. Decide whether convergence
of stored bytes matters, for example for log hashing across peers.

## 4. Smaller gaps

- **The Postgres existing-row lock (`forUpdate`) is not test-proven.** Removing it still passes the
  stored-DID concurrent test; only the first-merge race test discriminates. Needs a test where two
  merges on an existing row interleave.
- **`NOT_MEMBER` conflates saturation.** A saturated epoch reports `NOT_MEMBER`, and only `cause`
  distinguishes it. Consider a distinct reason.
- **Subject-signed root grants skip `nbf` (pre-existing).** Check whether this is intended and
  matches member grants.
