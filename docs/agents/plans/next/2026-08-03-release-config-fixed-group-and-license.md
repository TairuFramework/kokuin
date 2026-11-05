# Release config: LICENSE

**Status:** next
**Origin:** split out of `next/2026-07-02-ci-release-gating.md` on 2026-08-03 (triage) — these
two land in minutes and stop active bleeding, so they should not wait behind the pipeline work.

## Context

The fixed release group landed with the [crypto provider integration](../completed/2026-11-04-crypto-provider-integration.complete.md): every published package, otel included, moves together under `versioning.fixed`.
Every package still declares `"license": "MIT"` and no LICENSE file exists at the repository root.

## Work

### Add the LICENSE file

MIT, at the repo root, matching the `"license": "MIT"` every package already declares.

## Out of scope

Everything else from the original item — turbo task wiring, firmware CI, SLIP-0010 vectors,
workflow pinning, doc-snippet gating — stays in `next/2026-07-02-ci-release-gating.md`.
