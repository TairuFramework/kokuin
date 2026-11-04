# Verify the e2e-node keyring behaviour on Linux — completed

**Status:** complete
**Date:** 2026-11-04
**Origin:** `completed/2026-07-14-keystore-contract.complete.md` — the recorded watch-item.

## Context

The keystore contract work added an e2e test covering concurrent `provideAsync` **without**
`lockPath`. On macOS both racers throw, and the test asserts that. The plan recorded that the
Linux / gnome-keyring manifestation may instead diverge (one racer wins, the other observes a
different key) and left it unverified until the first real CI run of
`.github/workflows/e2e-node.yml`. Nothing tracked checking that result.

Cheap to close: read one CI run. Left open, it is either a passing test nobody confirmed or a
platform-dependent flake waiting for a contributor.

## Work

- Read the most recent `e2e-node.yml` run on Linux. If it never ran, trigger one.
- If Linux diverges from the macOS assertion, relax the test to accept both outcomes and
  document the platform split in the `KeyEntry.provideAsync` contract docstring
  (`packages/token/src/keystore.ts`) — the without-`lockPath` case is explicitly outside the
  idempotency guarantee, so divergence is contract-legal and belongs in the docs.
- If Linux matches, delete the watch-item and close this.

## Outcome

Linux diverges as predicted: both racers succeed with different DIDs and only one survives in
the keyring. The test already accepted that manifestation, but it was flaky on CI and on `main`
(Node E2E runs 111, 114, 117 and 124 failed on its "race did not manifest within 12 rounds"
assertion).

The cause was the harness, not the platform. The parent wrote the start file straight after
spawning, before either child had booted, so each child passed the barrier as soon as it
started and startup jitter decided the order. On a local gnome-keyring the race manifested in
about 9% of rounds, so a 12-round run missed it roughly one time in three.

Fixed in `tests/e2e-node`:

- Each child warms its keyring path with one throwaway async read, writes a ready file, and
  spins on the start file without sleeping.
- The parent releases the start file only once both ready files exist, and fails fast with
  both racers released if either exits early or neither is ready within 20 seconds.

Measured locally the race now manifests in about 50% of rounds. The unlocked test now allows
24 rounds instead of 12, so a run should practically never miss it: in 92 local runs after the
fix, two failed without captured output and 60 further runs, 15 under CPU load, all passed. The platform split is documented on `KeyEntry.provideAsync` in
`packages/token/src/keystore.ts`.
