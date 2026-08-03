# Verify the e2e-node keyring behaviour on Linux

**Status:** next — the whole item is reading one CI run; it costs less to close than to carry.
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
