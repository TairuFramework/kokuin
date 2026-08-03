# otel: package docs and dead surface

**Status:** backlog
**Origin:** `completed/2026-07-02-audit.complete.md` (Medium: otel undocumented, unused attr)

## Context

`@kokuin/otel` is a hard `workspace:^` dependency of all five fixed-group packages. The
architecture docs now cover it; its own README and its dead surface do not.

## Work

### otel has no README and ships an unused dep

Partly resolved on 2026-08-03: the architecture review added `@kokuin/otel` to AGENTS.md,
`docs/agents/architecture.md`, and the root README. Still open — the package has no README of
its own and declares an unused `@opentelemetry/api` dep. Write the README, and drop or use the
dep.

### `AUTH_ALGORITHM` attribute defined, never used

`packages/otel/src/index.ts:13` — dead surface, or missing instrumentation in `token.sign`.
Either wire it into `token.sign` or remove it.

## Out of scope

- otel's own release policy (fixed group or floating) — moved on 2026-08-03 to
  `next/2026-08-03-release-config-fixed-group-and-license.md`, which owns the fixed-group
  decision for the whole repo.
