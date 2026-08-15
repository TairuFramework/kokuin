# Architecture

kokuin (刻印, "engraved seal") is the identity / auth / keys layer.

## Packages

token, jwe, capability, controller, and per-environment keystores (browser, node, deterministic,
expo, electron, ledger-device). The `KeyEntry` / `KeyStore` contracts live in `@kokuin/token`,
as does the `DIDMethodResolver` interface through which a method whose keys are not in its
identifier is injected -- `@kokuin/controller` depends on token for signing, so the reverse import
would be a cycle.

- `@kokuin/jwe` -- JWE encryption, split out of token because it was the sole `@noble/ciphers`
  consumer and verify-only consumers were paying for a cipher they never called.
- `@kokuin/controller` -- the `did:kokuin:` profile DID: a KERI-style key event log, the fold that
  turns it into key state, branch selection, and the resolver that plugs the method into the rest.
  See [../reference/controller.md](../reference/controller.md) and
  [../reference/security.md](../reference/security.md).

Three supporting packages sit beside them:

- `@kokuin/otel` -- the `kokuin` tracer factory with the shared span and attribute names.
- `@kokuin/keystore-conformance` -- private, never published. The framework-agnostic suite
  (`keyStoreConformanceCases`, `mutableKeyStoreConformanceCases`) that every keystore backend
  runs to prove it honours the contract documented in `@kokuin/token`.
- `@kokuin/controller-conformance` -- private, same habit. `runControllerConformance(impl)` is the
  contract every `did:kokuin:` implementation runs. A contract, not a proof of security: it once
  passed five Criticals, because it only ever presented equal-length, cap-free branches.

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
