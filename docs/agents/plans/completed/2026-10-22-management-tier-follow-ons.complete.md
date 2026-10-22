# Management tier follow-ons — completed

**Status:** complete
**Date:** 2026-10-22
**Branch:** `management-tier-on-log` (`572d431`), on top of the management tier itself.
**Origin:** `backlog/2026-10-21-management-tier-follow-ons.md`, reviewed as release cleanup. No
spec or plan: a small change made directly from the backlog note.

## What was done

- **`nbf` on the empty-chain subject arm.** `checkDelegationChain` with no remaining links and
  `iss === sub` checked `exp` and `iat` but not `nbf`. The member arm beside it and the subject
  arm of `checkCapability` both checked all three. Links reached through the walk were never
  exposed, since `verifyToken` checks `nbf` on each. Fixed, with a test in `capability/test/lib.test.ts`.
- **The Postgres existing-row lock is test-proven.** `tests/integration/test/concurrency.test.ts`
  races merges on an existing controller row from two connections (two `HozonDB` instances on one
  database, 20 rounds, alternating which is issued first). With `forUpdate` removed it fails with
  one event lost; with it, both land. The earlier single-instance test could not discriminate.

## Rulings

- **`NOT_MEMBER` keeps covering a saturated epoch.** `@kokuin/capability` depends only on the
  method-agnostic `@kokuin/token` contract, so a distinct reason would mean matching a
  controller-only error string. The `cause` carries `EPOCH_SATURATED`, as `capability.md`
  documents. Reopen if the token contract grows a typed "subject unavailable" error.
- **The trusted `LogStore`, first-copy signatures and held re-resolution cost stay as they are.**
  They remain in the backlog note with the trigger that should reopen each.
