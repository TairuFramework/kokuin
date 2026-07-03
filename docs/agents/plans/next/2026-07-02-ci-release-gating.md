# CI and release gating

**Status:** next
**Origin:** `completed/2026-07-02-audit.complete.md` (Critical #5, High: turbo/ledger-CI/SLIP-0010, Medium: CI pin/LICENSE)

## Context

The build/test/release plumbing does not actually gate: fresh-clone `pnpm test` fails,
firmware and derivation vectors are never exercised, versions have diverged, and CI depends
on an unpinned external workflow. Make the pipeline enforce what it claims.

## Work

### Changeset fixed release group not configured (Critical #5)

`.changeset/config.json:5` has `"fixed": []` / `"linked": []`, but AGENTS.md documents that
token, capability, browser, node, deterministic release together. Versions already diverged
(token 0.1.1, capability 0.1.0, browser 0.1.2, node 0.1.1, deterministic 0.1.1). Configure
the `fixed` group.

### Tests don't depend on build; `clean` task is dead (High)

`turbo.json:9` — `test:types`/`test:unit` have no `dependsOn` on build, so a fresh-clone
`pnpm test` fails (types point at `lib/`). The `clean` task (`turbo.json:4`) matches no
package script (all use `build:clean`), so `build:js`'s `^clean` dependency is a no-op.

### Firmware never built in CI (High)

No workflow touches `apps/ledger`, and the Speculos suite auto-skips when the emulator is
absent (`describe.skipIf`), so `turbo run test:unit` green-lights without running the APDU
round-trip. C sources break silently. Add a firmware build + Speculos job.

### No SLIP-0010 test-vector assertion (High)

`packages/deterministic/test/derivation.test.ts:26` cites "Test Vector 1" but only asserts
key length and determinism. A wrong derivation (swapped IL/IR, wrong HMAC key) still passes.
Assert the vector's expected private-key hex.

### Reusable CI workflows pinned to `@main` (Medium)

`.github/workflows/*.yml` — kokuin CI can break with no commit here. Pin to a SHA or tag.

### No LICENSE file (Medium)

None anywhere, despite all packages declaring `"license": "MIT"` — nothing ships to npm.
Add the license file.

## Out of scope

- The security bug fixes those tests should cover — see the capability/token/keystore
  `next/` items.
