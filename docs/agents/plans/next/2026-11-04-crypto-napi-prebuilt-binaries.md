# Publish prebuilt Node-API crypto binaries

## Context

`@kokuin/crypto-node` runs Ed25519 signing and ES256 verification on `node:crypto` with a JavaScript low-S check. It delegates Ed25519 verification and blake3 to strict noble.
`@kokuin/crypto-napi` runs the Rust core through Node-API. Today it builds from source for the CI host only.
Both packages float independently, like `@kokuin/crypto-native`.

`@kokuin/crypto-napi` falls back to `@kokuin/crypto-node` when no prebuilt binary loads. The choice happens once, at provider construction.
This differs from the mobile no-fallback rule on purpose: Node has a conformant pure-JavaScript route, and an unsupported platform must not fail installation.

The [Node crypto benchmark gate](../../reference/crypto-node-benchmark.md) runs on x86_64 and arm64 CI runners and sets the package's routes.
Its matrix includes the record and vault call shapes measured on the [provider integration](../completed/2026-11-04-crypto-provider-integration.complete.md) branch.
Vault and record hashing use single `blake3` calls, which run natively on the calling thread.

## Work

1. Confirm the gate passes on both CI architectures.
2. Build prebuilt binaries for linux x64/arm64 (gnu and musl), macOS x64/arm64 and Windows x64/arm64.
3. Publish them as per-platform packages under `optionalDependencies`, with binary provenance.
4. Test the fallback to `@kokuin/crypto-node` on a platform with no matching binary.

## Acceptance

A clean install on each supported platform loads the native binary. An unsupported platform installs and uses `@kokuin/crypto-node`.
