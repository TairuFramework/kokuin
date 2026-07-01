# Architecture

kokuin (刻印, "engraved seal") is the identity / auth / keys layer.

## Packages

token, capability, and per-environment keystores (browser, node, deterministic, expo,
electron, ledger-device). The `KeyEntry` / `KeyStore` contracts live in `@kokuin/token`.
The BOLOS on-device firmware pairing with `ledger-device` lives under `apps/ledger`.

## Position in the stack

Depends downward on sozai; consumed by enkaku and kumiai. See the stack overview:
https://github.com/TairuFramework/kigu/blob/main/docs/stack.md
