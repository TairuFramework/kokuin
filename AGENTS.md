# kokuin

> Conventions: `kigu:conventions` skill (canonical -- do not restate).
> Stack map / sibling docs: `kigu:stack-map` skill.

## What this repo is

刻印 ("engraved seal") -- the identity / auth / keys layer. Depends downward on `@sozai`;
consumed by `@enkaku` (RPC) and `@kumiai` (MLS).

Identity primitives: JWT-style tokens, capabilities, and keystores per runtime (browser,
node, electron, expo, deterministic HD, ledger-device). Two supporting packages: `@kokuin/otel`
(tracer factory and span/attribute names) and `@kokuin/keystore-conformance` (private -- the
framework-agnostic suite that enforces the `KeyStore` / `KeyEntry` contract on every backend).

End-to-end suites live under `tests/` (`e2e-electron`, `e2e-expo`, `e2e-node`, `e2e-web`,
`ledger`). `pnpm-workspace.yaml` includes `tests/*` as workspace packages.

`apps/ledger` is the on-device BOLOS firmware (C, Ledger Nano S+/X) paired with
`@kokuin/ledger-device` over APDU -- not a pnpm package, built via its own Docker/Makefile.
The APDU protocol versions in lockstep with the host-side package.

## Guardrails

See the `kigu:conventions` skill. Repo-specific only:

- pnpm only.
- Cross-repo deps (`@sozai/*`) are published `^` ranges, never `workspace:`.
- token, capability, browser, node, and deterministic are bumped together by releaser judgement,
  not a changesets `fixed` group -- `updateInternalDependencies: "patch"` cascades bumps through
  the internal workspace dependency graph. `expo`, `electron`, and `ledger-device` are
  SDK/hardware-bound and float independently.
- All dev tooling and shared config comes from `@kigu/dev`. Extend `@kigu/dev/tsconfig.json`,
  `["@kigu/dev/biome.json"]`, and `@kigu/dev/swc.json`.
