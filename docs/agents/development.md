# Development

Shared build, test, and release workflow lives in the kigu `development` skill,
auto-loaded via the kigu plugin. See it for the pnpm / Turbo / SWC / Biome / Vitest
workflow and the `docs/agents/plans/` lifecycle.

## Repo-specific

Identity layer: token, capability, and per-environment keystores. The `KeyEntry` / `KeyStore`
contracts live in `@kokuin/token`.
