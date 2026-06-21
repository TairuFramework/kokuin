# kokuin

> **For AI agents:** 刻印 ("engraved seal") — the identity / auth / keys layer.
> token + capability + per-environment keystores. Depends downward on `@sozai`;
> consumed by `@enkaku` (RPC) and `@kumiai` (MLS).

## What this repo is

Identity primitives: JWT-style tokens, capabilities, and keystores per runtime
(browser, node, electron, expo, deterministic HD, ledger-device). Cross-repo deps
(`@sozai/*`) are published `^` ranges, never `workspace:`. The fixed group
(token, capability, browser, node, deterministic) releases together; `expo`,
`electron`, and `ledger-device` are SDK/hardware-bound and float independently.

`apps/ledger` is the on-device BOLOS firmware (C, Ledger Nano S+/X) paired with
`@kokuin/ledger-device` over APDU — not a pnpm package, built via its own Docker/Makefile.
The APDU protocol versions in lockstep with the host-side package.

## Conventions

Follow the `conventions` skill from the `kigu` marketplace (the canonical source of
truth). pnpm only. `type` not `interface`; `Array<T>` not `T[]`; never `any`; capital
`ID`/`HTTP`/`JWT`/`DID`; ES `#fields`, never `private`/`readonly`. Do not edit
generated files (`lib/`).

## Toolchain

All dev tooling and shared configs come from `@kigu/dev`. Extend
`@kigu/dev/tsconfig.json`, `["@kigu/dev/biome.json"]`, and `@kigu/dev/swc.json`.

See `../kigu/docs/repo-split-design.md` for the broader monorepo-split architecture.
