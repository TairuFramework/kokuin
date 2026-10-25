# Rust Crypto Benchmark Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** determine whether strict Rust crypto improves real-device latency before changing existing public APIs.

**Stage:** executing
**Mode:** tasks

**Architecture:** build an isolated Rust core and minimal Nitro binding inside kokuin. Compare complete native calls against strict noble on Hermes. Keep all existing consumers unchanged until the gate passes.

**Tech Stack:** Rust, ed25519-dalek, curve25519-dalek, p256, blake3, zeroize, cbindgen, Nitro Modules, Expo 58, React Native 0.88.

**Spec:** [Rust crypto backend](../specs/2026-10-24-rust-crypto-backend-design.md)

## Global Constraints

- "Benchmarks first, and they gate."
- "No automatic backend detection."
- "Private key bytes are zeroized in Rust (`zeroize`) after use; nothing is cached across calls."
- "Batch verification is a loop of strict single verifies inside the backend."
- Preserve all existing public APIs during this spike.
- Treat the spec's design approval and real-device access as execution prerequisites.
- Use pnpm for JavaScript tooling and Cargo for Rust.

## Review Focus

- Mutated subarray inputs must still produce results for their original visible bytes. Task 2 tests this boundary.
- Exceptional signing paths must erase every native seed copy. Task 2 tests owner cleanup.
- Cached keys and warmed runtimes must not hide subgroup-check costs. Task 3 records cold and warm runs separately.
- Missing devices or noisy timings must leave the gate pending. Task 3 tests the gate evaluator.
- Batch-only improvements must not imply improved single calls. Task 3 evaluates each operation variant separately.

## Proposed decisions

These are planning choices, not measured results or additional agreements with Paul.

- Keep `getPublicKey` on noble. Identity construction remains synchronous where it does not verify logs.
- Use Rust 2024 edition. Select and pin compatible released crate, Nitro, NDK and Xcode versions during Task 1.
- Initially support iOS arm64 devices, arm64/x86_64 simulators, Android arm64-v8a and x86_64.
- Record actual native deployment floors from successful Expo 58 builds. Do not lower or guess those floors.
- Start with arrays of byte-buffer descriptors. Compare packed batches only if descriptor overhead materially affects the gate.
- Benchmark single and batch variants independently for Ed25519 sign, Ed25519 verify, ES256 verify and blake3.
- A native provider may use documented noble routes for variants that fail the gate.
- Native initialisation failures always throw, even when some configured variants use noble.

## File map

| Files | Responsibility |
| --- | --- |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | Reproducible Rust workspace |
| `crates/kokuin-crypto/{Cargo.toml,src/lib.rs,src/ed25519.rs,src/p256.rs,src/hash.rs}` | Binding-independent strict operations |
| `crates/kokuin-crypto/tests/smoke.rs` | Known answers and rejection cases |
| `crates/kokuin-crypto-ffi/{Cargo.toml,src/lib.rs,cbindgen.toml}` | Checked C ABI |
| `crates/kokuin-crypto-ffi/tests/abi.rs` | Invalid lengths, statuses and allocation ownership |
| `packages/crypto-native/{package.json,nitro.json,src/Crypto.nitro.ts,cpp/HybridCrypto.hpp,cpp/HybridCrypto.cpp}` | Private spike binding |
| `packages/crypto-native/{KokuinCrypto.podspec,react-native.config.js,android/build.gradle,android/CMakeLists.txt}` | Mobile linking |
| `packages/crypto-native/cpp/test/OwnershipTest.cpp` | Native input cleanup and output lifetime |
| `scripts/build-crypto-native.mjs` | Local cross-builds for the spike |
| `tests/e2e-expo/crypto/{spike.ts,benchmark.ts,strict-noble.ts,gate.ts,gate.test.ts}` | Correctness, timing and gate evaluation |
| `tests/e2e-expo/components/CryptoBenchmark.tsx` | Explicit benchmark trigger and export |
| `docs/reference/crypto-benchmarks/` | Durable reports, raw results and routing decisions |

Also modify `pnpm-workspace.yaml`, `pnpm-lock.yaml`, `tests/e2e-expo/package.json` and `tests/e2e-expo/App.tsx`.
Keep the spike package private and list `@kokuin/crypto-native` exactly in `versioning.ignore` until rollout.
Use existing `@kigu/dev` package configuration. Nitro-generated interfaces may follow its generator's required syntax.

### Task 1: build a strict, binding-independent baseline

**Interfaces:** produce `sign_ed25519(seed: &[u8], message: &[u8]) -> Result<[u8; 64], CryptoError>`.
Produce `verify(algorithm: Algorithm, signature: &[u8], message: &[u8], public_key: &[u8]) -> bool`.
Produce `hash_blake3(input: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError>`.
Expose `Algorithm::{Ed25519, Es256}`. Batch methods loop over these single-operation functions without algebraic batching.

- [ ] Add `smoke.rs` cases for RFC 8032 empty-message signing, valid verification, mutated messages and identity-point rejection.
- [ ] Add ES256 cases for compact low-S signatures, their high-S twins and raw-message versus prehash confusion.
- [ ] Add official blake3 empty-input outputs at lengths 16, 32 and 64.
- [ ] Run `cargo test -p kokuin-crypto --test smoke`. Expect failure before implementation.
- [ ] Implement canonical A/R decoding, non-small-order torsion-free checks, canonical S and dalek strict verification.
- [ ] Implement compact P-256 parsing, SEC1 key parsing, explicit high-S rejection and exactly one SHA-256 hash.
- [ ] Implement Ed25519 seed signing and blake3 output, with zeroising signing-key ownership.
- [ ] Implement the identical strict noble baseline in `strict-noble.ts`, including both A and R checks.
- [ ] Pin the Rust toolchain and crate versions in lockfiles after successful host tests.
- [ ] Run `cargo test --workspace --locked`. Expect every known-answer and rejection case to pass.
- [ ] Commit this independently testable baseline as `feat: add strict Rust crypto benchmark core`.

### Task 2: expose complete, safe async calls through Nitro

**Interfaces:** consume Task 1 functions. Produce private `Crypto` Hybrid Object operations matching the spec's six async operation shapes.
The TypeScript adapter accepts `Uint8Array` views. The bridge accepts their backing buffers plus byte offsets and lengths.
Produce explicit `createSpikeCrypto()` construction that throws when native registration is unavailable.

The C ABI uses pointer/length descriptors and integer status codes. Rust owns output allocations and exports their release function.
Verification failure is a boolean result. Invalid requests and infrastructure failures are statuses converted into Promise rejections.

- [ ] Add failing ABI tests for empty buffers, invalid lengths, offset overflow, unknown algorithms and mixed-validity verification batches.
- [ ] Add native ownership tests for successful signing, early rejection and worker-dispatch failure cleanup.
- [ ] Add mobile checks using padded backing buffers, nonzero offsets and immediate caller mutation after invocation.
- [ ] Run `cargo test -p kokuin-crypto-ffi --locked`. Expect missing-ABI failures before implementation.
- [ ] Generate the C header with cbindgen and implement checked descriptors, Rust output allocation and matching release.
- [ ] Prevent Rust panics from unwinding across C. Translate recoverable failures without terminating the app.
- [ ] Copy all input views synchronously into native owners before dispatching `Promise<T>::async` work.
- [ ] Use a zeroising C++ owner for seed-bearing copies and zeroising Rust owners for seed temporaries.
- [ ] Attach native output allocation release to the returned owning Nitro buffer's lifetime.
- [ ] Add cross-build and link configuration for the proposed iOS slices and Android ABIs.
- [ ] Pin Nitro and native tool versions after successful iOS and Android link checks.
- [ ] Build the Expo development client with `pnpm --filter e2e-expo ios` and `pnpm --filter e2e-expo android`.
- [ ] Run smoke checks on both platforms. Expect exact baseline parity, immutable input snapshots and no stale output pointers.
- [ ] Run native ownership tests with sanitizers on a supported host. Expect no leaks or invalid access.
- [ ] Commit the binding as `feat: add async Nitro crypto benchmark binding`.

### Task 3: run and record the real-device gate

**Interfaces:** produce `evaluateGate(samples: Array<BenchmarkSample>): GateReport` in `gate.ts`.
`BenchmarkSample` records platform, device, operation, backend, message size, batch size, warm state and timing samples.
`GateReport` records `status: 'pending' | 'stop' | 'proceed'` and one native/noble decision per measured variant.
The report includes source revision, exact dependency versions, build flags, device OS and the chosen batch wire format.

Proposed workloads: message sizes 0, 32, 256, 4096 and 65536 bytes. Batch sizes: 1, 8, 32 and 128.
Measure Ed25519 signing, both verification algorithms and blake3 lengths 16, 32 and 64 separately.
Include valid, invalid and mixed verification workloads. Include repeated and distinct public keys.

Proposed gate: use 100 warmups and five independently ordered runs of at least 200 timed samples per cell.
Retain a variant only when native median wall latency is at least 10% lower in every run on both platforms.
Require native p95 wall latency and JS-thread occupation to remain no worse than strict noble for that cell.
Native routing must cover all tested message sizes for that operation/output-length/batch-size cell.
Single calls and batches of one remain separate cells. Unsupported sizes use a documented noble route.
The 10% margin is a conservative planning choice against measurement noise, not a requirement from the original spec.

- [ ] Add evaluator tests for missing platforms, insufficient runs, noisy results, batch-only wins and complete failure.
- [ ] Assert missing evidence yields `pending`, complete failure yields `stop`, and supported wins yield `proceed`.
- [ ] Run `pnpm exec vitest run tests/e2e-expo/crypto/gate.test.ts`. Expect failure before implementation.
- [ ] Implement the timing harness, deterministic fixtures and report evaluator.
- [ ] Measure existing noble separately from strict noble. Use strict noble for pass/fail decisions.
- [ ] Include input copying, marshalling, dispatch and Promise settlement in native wall latency.
- [ ] Record synchronous JS work and timer/frame delays under sustained load separately from wall latency.
- [ ] Confirm worker execution using native thread evidence. Exclude debugger-attached runs and console logging from measurements.
- [ ] Build Release clients using `pnpm --filter e2e-expo ios:release` and `pnpm --filter e2e-expo android:release`.
- [ ] Run the workload matrix on a physical iPhone and physical Android device.
- [ ] Save raw samples and the report under `docs/reference/crypto-benchmarks/YYYY-MM-DD-spike/`.
- [ ] Run the evaluator tests again. Expect all pending, stop and proceed assertions to pass.
- [ ] Record exact native/noble routes, target floors and pinned tool versions in the report.
- [ ] If the gate is pending, leave rollout blocked on evidence. Do not substitute simulator performance.
- [ ] If the gate says stop, retain the report and stop before any existing public API changes.
- [ ] If the gate says proceed, update the conditional rollout plan with the measured routes before execution.
- [ ] Commit results as `docs: record mobile crypto benchmark gate`.

## Handoff

The next plan is [Rust Crypto Backend](2026-10-25-rust-crypto-backend.md).
No benchmark results exist when this plan is written. Device access is required only when executing Task 3.
