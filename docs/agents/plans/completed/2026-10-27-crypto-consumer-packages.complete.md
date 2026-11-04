# Standalone crypto providers -- completed

**Status:** complete
**Date:** 2026-10-27
**Branch:** `rust-crypto-backend`
**Implementation:** through `552f973`

The completed scope supplies installable standalone providers, native distribution tooling and physical Android probe evidence.
Paul accepted this scope for branch closeout on 2026-10-27.
Existing API migration, full benchmark qualification and publication remain separate follow-on work.

## Delivered

`@kokuin/crypto` exports the shared asynchronous contract and strict noble implementation.
`@kokuin/crypto-native` exports explicit Nitro construction backed by a binding-independent Rust core and checked C ABI.
Both provide Ed25519 signing, Ed25519/ES256 verification and blake3, including ordered batch operations.
The private `@kokuin/crypto-conformance` suite exercises the same contract across providers.

Native packages contain prebuilt iOS device/simulator and Android ARM64/x86_64 libraries, generated bindings and dependency licences.
Consumer fixtures install tarballs outside the workspace and build without Cargo.
Source fingerprints, binary hashes and complete binding-file checks reject incomplete or stale distributions.
pnpm manages contributor Rust dependencies, the pinned toolchain and mobile targets.
Android package builds honour the supported subset requested by the consuming application.

## Design decisions retained

- Nitro supplies one shared C++ binding and worker dispatch. Rust remains independent of the React Native binding.
- Applications select native explicitly. Native registration, ABI and execution failures never trigger silent fallback.
- Ed25519 checks canonical A/R/S and rejects small-order and mixed-order A/R points.
- ES256 accepts compact signatures and SEC1 keys, hashes raw messages once and rejects high-S signatures.
- Input views and batch membership are captured before suspension. Native seed copies are erased on success and failure.
- Returned buffers retain Rust ownership until release. Batch verification loops strict single verifications rather than algebraically combining signatures.
- Existing consumers keep their current APIs. Future operation routing depends on complete measurements rather than runtime backend detection.

## Verification

All 92 repository tasks passed, alongside Rust tests, formatting, clippy and native ownership sanitizers.
Independent review findings concerning batch-array mutation and incomplete generated-file validation were corrected with regressions.
Packed Release consumers passed shared conformance on iOS simulator, Android emulator and the physical Galaxy A35.
The ARM64-only consumer build and physical conformance passed after correcting ABI selection.

The exploratory Android probe found faster native signing/verification and slower native blake3 for its selected small workloads.
Its reduced repetition counts and single-device coverage do not qualify production routes.
Packages remain prepared at 0.1.0 without registry publication.

## Durable references and follow-ons

- [Provider contract and adoption](../../../reference/crypto-provider.md)
- [Consumer verification](../../../reference/crypto-consumer-verification.md)
- [Physical Android probe and raw data](../../../reference/crypto-benchmarks/2026-10-27-android-probe/README.md)
- [Complete benchmark qualification](../next/2026-10-27-crypto-benchmark-gate.md)
- [Package release validation](../next/2026-10-27-crypto-package-release.md)
- [Conditional existing API migration](../backlog/2026-10-27-crypto-provider-integration.md)

These follow-ons replace the earlier end-to-end rollout plan and preserve its unresolved design constraints.
