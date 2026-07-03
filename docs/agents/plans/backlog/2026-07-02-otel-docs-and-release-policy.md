# otel: docs and release policy

**Status:** backlog
**Origin:** `completed/2026-07-02-audit.complete.md` (Medium: otel undocumented, unused attr)

## Context

`@kokuin/otel` is a hard `workspace:^` dependency of all five fixed-group packages but sits
outside the documented release and architecture surface. Tidy its docs, release policy, and
dead surface.

## Work

### otel is undocumented and outside release policy

Absent from AGENTS.md, `docs/agents/architecture.md`, and root README; has no README of its
own; no changeset group; declares an unused `@opentelemetry/api` dep. Document it, place it
in the release policy, and drop or use the unused dep.

### `AUTH_ALGORITHM` attribute defined, never used

`packages/otel/src/index.ts:13` — dead surface, or missing instrumentation in `token.sign`.
Either wire it into `token.sign` or remove it.

## Out of scope

- Fixed release group configuration for the core packages — see
  `next/2026-07-02-ci-release-gating.md`.
