# Architecture

kokuin (刻印, "engraved seal") is the identity / auth / keys layer.

## Packages

token, capability, and per-environment keystores (browser, node, deterministic, expo,
electron, ledger-device). The `KeyEntry` / `KeyStore` contracts live in `@kokuin/token`.

Two supporting packages sit beside them:

- `@kokuin/otel` -- the `kokuin` tracer factory with the shared span and attribute names.
- `@kokuin/keystore-conformance` -- private, never published. The framework-agnostic suite
  (`keyStoreConformanceCases`, `mutableKeyStoreConformanceCases`) that every keystore backend
  runs to prove it honours the contract documented in `@kokuin/token`.

## Tests

End-to-end suites are workspace packages under `tests/`, included via `tests/*` in
`pnpm-workspace.yaml`: `e2e-electron`, `e2e-expo`, `e2e-node`, `e2e-web`, and `ledger`
(Speculos APDU round-trip against the firmware).

## Firmware

The BOLOS on-device firmware pairing with `ledger-device` lives under `apps/ledger`. It is not
a pnpm package -- it builds via its own Docker/Makefile.

## Position in the stack

Depends downward on sozai; consumed by enkaku and kumiai. See the stack overview:
https://github.com/TairuFramework/kigu/blob/main/docs/stack.md
