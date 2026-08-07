# Release config: fixed group and LICENSE

**Status:** next
**Origin:** split out of `next/2026-07-02-ci-release-gating.md` on 2026-08-03 (triage) — these
two land in minutes and stop active bleeding, so they should not wait behind the pipeline work.

## Context

The release policy says token, capability, browser, node and deterministic release together,
but nothing declares or enforces it, so the group has drifted apart with every release:

| Package | Version (2026-08-03) |
|---------|----------------------|
| `@kokuin/token` | 0.3.0 |
| `@kokuin/capability` | 0.2.1 |
| `@kokuin/browser` | 0.2.0 |
| `@kokuin/node` | 0.3.0 |
| `@kokuin/deterministic` | 0.2.0 |

Five packages, five versions. Each release widens the spread, and the drift is what makes
downstream adoption hard to reason about (see
`backlog/2026-08-03-downstream-keystore-contract-adoption.md`, where kumiai sits two minors
behind on capability). Separately, every package declares `"license": "MIT"` and no LICENSE
file exists anywhere, so nothing is legally shippable to npm.

## Work

### Configure the fixed release group

Set the group under `versioning.fixed` in `pnpm-workspace.yaml`:

```yaml
versioning:
  fixed:
    - ['@kokuin/token', '@kokuin/capability', '@kokuin/browser', '@kokuin/node', '@kokuin/deterministic']
```

`expo`, `electron` and `ledger-device` are SDK/hardware-bound and float independently — they
stay out. (Release tooling moved from changesets to pnpm's built-in versioning on 2026-08-07;
this item was written against `.changeset/config.json`.)

Decide what to do about the existing spread: the first fixed release levels all five to one
version, which means browser/deterministic jump two minors in a single release. That is
allowed pre-1.0 but should be a deliberate choice, not a surprise in a release PR.

### Decide otel's release policy

`@kokuin/otel` is a hard dependency of all five fixed-group packages but sits outside the
group. Either add it to the fixed group or record why it floats. Carried over from
`backlog/2026-07-02-otel-docs-and-release-policy.md`, which keeps the remaining otel items.

### Add the LICENSE file

MIT, at the repo root, matching the `"license": "MIT"` every package already declares.

## Out of scope

Everything else from the original item — turbo task wiring, firmware CI, SLIP-0010 vectors,
workflow pinning, doc-snippet gating — stays in `next/2026-07-02-ci-release-gating.md`.
