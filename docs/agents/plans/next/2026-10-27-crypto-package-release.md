# Validate and release standalone crypto packages

## Context

`@kokuin/crypto` and `@kokuin/crypto-native` are prepared at 0.1.0 and verified through independent tarball consumers.
The [completed delivery](../completed/2026-10-27-crypto-consumer-packages.complete.md) records the implementation boundary.
Publishing remains a separately authorised action.
The expanded adversarial corpus and remaining runtime checks precede production-readiness claims.

## Work

1. Run the new native cross-build/package workflow remotely and retain its artifacts.
2. Exercise portable imports in a fresh browser runtime.
3. Exercise supported x86_64 targets at runtime when suitable hosts are available.
4. Expand the shared corpus with pinned RFC 8032, Wycheproof Ed25519/P-256 and official blake3 vectors.
5. Record source revisions, licences and explicit outcomes under the stricter project verification policy.
6. Generate one checked corpus for TypeScript and Rust, including generator drift checks and deliberately incorrect-provider tests.
7. Cover canonical encodings, scalar boundaries, small/mixed-order points, off-curve keys, invalid r/s, high-S and double hashing.
8. Cover batch ordering, snapshots, detached/shared buffers, independent outputs and all hash-length bounds.
9. Repeat shared cases through noble, Rust and packed native consumers.
10. Verify both default and single-ABI Android builds, generated registration files, complete notices and binary provenance.
11. Preserve the absence of Nitro and Rust requirements in portable consumer installations.
12. Use `kigu:releasing` to inspect versions, public access and release intents before any separately requested publication.

The complete [physical benchmark gate](2026-10-27-crypto-benchmark-gate.md) remains necessary for qualified routes and existing API migration.
An experimental standalone release does not establish that qualification.

## Acceptance

Packed artifacts install outside the monorepo, pass the expanded shared suite and contain every supported binary and required licence.
Documentation distinguishes experimental standalone usage from qualified operation routing and future API changes.
