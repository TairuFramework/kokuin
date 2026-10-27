# Consumer Crypto Packages Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** make standalone noble and native providers installable without migrating existing consumer APIs.

**Stage:** qa
**Mode:** tasks

**Execution state:** standalone packages implemented and independently reviewed. Consumer acceptance remains open.
Packed consumer Release builds and all 15 conformance cases per provider passed on iOS simulator and Android emulator.
Existing API migration and physical-device performance measurements remain gated in the parent plans.

**Architecture:** publish a shared provider contract with strict noble operations and an explicit Nitro provider.
Native packages contain prebuilt Rust libraries, generated bindings and dependency licences.
The existing physical-device benchmark gate continues to govern changes to token, controller and records APIs.

**Tech Stack:** TypeScript, noble, Rust, Nitro, pnpm, Vitest, Expo.

**Spec:** [Rust crypto backend](../specs/2026-10-24-rust-crypto-backend-design.md).

## Scope

Paul requested continued implementation for consumer adoption on 2026-10-27, rather than closing the workstream as partial.
Physical phones remain unavailable. Standalone package preparation preserves the benchmark gate on existing API migration.
Publishing packages remains a separate action.

## Global constraints

- Keep noble as the default. Require explicit native construction and propagate native failures.
- Preserve strict Ed25519 subgroup checks, low-S P-256 and raw-message hashing exactly once.
- Preserve byte-view snapshots, batch ordering and zeroising native ownership.
- Do not require Rust, pnpm or build-time crate downloads in a consumer application.
- Keep existing token, controller and records public APIs unchanged.
- Make no native performance claims without physical-device evidence.

## Review focus

- Node and browser imports of the portable provider must not load Nitro or native binaries.
- Packed native packages must reject missing or stale binaries before distribution.
- Native construction must reject missing registration and incompatible ABIs without fallback.
- Both providers must reject detached/shared inputs and preserve subarray snapshots.
- Consumer installs must resolve published package ranges rather than monorepo paths.

### Task 1: extract the portable provider contract and strict baseline

**Files:** create `packages/crypto/{package.json,tsconfig.json,tsconfig.test.json,src/types.ts,src/noble.ts,src/index.ts,test/contract.test.ts}`.
Create `packages/crypto-conformance/{package.json,tsconfig.json,tsconfig.test.json,src/index.ts,test/index.test.ts}`.
Modify the native provider and Expo baseline to consume the shared contract.

**Interfaces:** export `CryptoProvider`, `CryptoAlgorithm`, `SignItem`, `VerifyItem` and `nobleCrypto` from `@kokuin/crypto`.
Export `cryptoConformance(provider: CryptoProvider): Array<{ name: string; run(): Promise<void> }>` from the private suite.
Retain all six existing async operation signatures and the hash length range 1 through 65536.

- [x] Add contract tests for known answers, strict verification, malformed batches, buffer snapshots and independent outputs.
- [x] Run the tests before implementation and confirm the missing portable provider causes failure.
- [x] Extract strict noble operations and shared types without importing Nitro.
- [x] Add framework-independent checks reusable by the mobile test app and both providers.
- [x] Prove the suite rejects a deliberately incorrect provider.
- [x] Build the new packages, run their tests and run the repository suite.
- [x] Commit the portable contract and conformance foundation.

### Task 2: prepare the explicit native provider for distribution

**Files:** modify `packages/crypto-native/{package.json,src/index.ts,src/provider.ts,README.md,KokuinCrypto.podspec}`.
Create `scripts/check-crypto-package.mjs` and package validation tests.
Create dependency licence generation and explicit package file lists.

**Interfaces:** export `createNativeCrypto(): CryptoProvider` with a synchronous ABI check.
Keep the benchmark factory available until its callers migrate.
Package validation rejects missing slices, stale fingerprints, missing generated glue and missing licence notices.

- [x] Add tests for construction failures, corrupt responses, missing artifacts and stale packed inputs.
- [x] Watch those tests fail before implementing the public factory and packaging checks.
- [x] Set public package metadata, tested peer ranges and explicit distribution files.
- [x] Include iOS device/simulator and both Android libraries with generated glue and licence notices.
- [x] Require successful artifact validation before packing or publishing.
- [x] Build and pack both public packages. Inspect their contents and rewritten dependency ranges.
- [x] Commit the native distribution preparation.

### Task 3: verify consumer installation and document adoption

**Files:** create packed-package consumer verification tooling and permanent provider documentation.
Modify native cross-build CI and the Expo checks to consume the shared conformance suite.

**Interfaces:** install tarballs into a temporary directory outside the workspace.
Portable imports must execute known-answer operations without loading Nitro.
Mobile consumers must link shipped libraries without invoking Cargo.

- [x] Install both tarballs into independent consumer fixtures.
- [x] Run portable known-answer checks and verify no native dependencies enter its graph.
- [x] Build mobile consumers from packed packages with Cargo absent from PATH.
- [x] Run shared conformance checks on simulator and emulator where tooling permits.
- [x] Document installation, explicit construction, supported targets and unmeasured performance.
- [x] Run repository, Rust, native ownership and packaging checks.
- [x] Obtain one fresh review of the final changes and address material findings.
- [x] Commit validated consumer adoption tooling and record any environmental limitations.

## Deferred work

Physical-device measurements and the conditional full provider migration remain in the existing plans.
The larger adversarial corpus, broader provider integration and coordinated breaking release remain rollout prerequisites.
