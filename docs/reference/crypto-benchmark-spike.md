# Mobile crypto benchmark spike

The private spike compares current noble, strict noble and Rust through Nitro 0.37.1.
Existing token, controller and record APIs remain unchanged until physical-device measurements pass the gate.

## Build

1. Install dependencies with `pnpm install --frozen-lockfile`.
2. Build JavaScript packages with `pnpm run build`.
3. Build iOS binaries with `node scripts/build-crypto-native.mjs ios`.
4. Build Android binaries with `node scripts/build-crypto-native.mjs android`.
5. Regenerate stale Expo projects with `pnpm --filter e2e-expo exec expo prebuild --no-install`.
6. Build Release clients with `pnpm --filter e2e-expo ios:release` and `pnpm --filter e2e-expo android:release`.

pnpm 12.15.0 installs the crates locked in `Cargo.lock` and the toolchain declared in `rust-toolchain.toml`.
The toolchain includes Rust 1.99.1, clippy, rustfmt, llvm-tools and all five mobile targets.
llvm-tools supplies the shared library required by rust-objcopy on macOS without rustup's loader environment.
This avoids the [Rust distribution loader issue](https://github.com/rust-lang/rust/issues/163947).
The first install downloads these targets on every host, including hosts running only JavaScript checks.
Run Rust commands through `pnpm exec` to select the managed toolchain without requiring rustup.
Cargo still compiles the crates. `Cargo.lock` and `pnpm-lock.yaml` remain independent.
pnpm's Cargo support is experimental. Its generated sources and toolchain links live in ignored `.pnpm/` directories.
The optional include in `.cargo/config.toml` selects those sources and permits normal Cargo fetching when absent.

The Android builder uses NDK `27.1.12297006`. `KOKUIN_ANDROID_NDK` overrides its path.
The binaries target iOS 16.4 and Android API 24.
Supported targets include iOS arm64 devices, arm64/x86_64 simulators, Android arm64-v8a and x86_64.
App builds link the prebuilt libraries without invoking Cargo.
Generated binaries remain ignored build outputs during the spike.
Release test scripts prepare missing or stale binaries on fresh checkouts, including CI.
Source and artifact fingerprints prevent a new revision from silently reusing old Rust binaries.
Matching binaries work without Cargo on the app builder's PATH.
The Android builder supports macOS and Linux NDK hosts.
After Rust or build-recipe changes, the preparation helper requires the Rust toolchain again.

## Correctness checks

```sh
pnpm exec cargo test --workspace --locked --offline
pnpm exec cargo clippy --workspace --all-targets --locked --offline -- -D warnings
pnpm --filter @kokuin/crypto-native test:native
pnpm test
```

Launch the Expo test app and select **Run crypto checks**.
The **Crypto checks: OK** marker covers all six methods, verification, subarray snapshots and retained output ownership.
The native worker rejects execution on its caller thread.
`tests/e2e-expo/.maestro/crypto-checks.yaml` automates this check.
Simulator builds need normal local signing because the existing SecureStore tests require entitlements.
Disabling simulator signing prevents the test app from reaching its crypto checks.

## Measurements

1. Capture build metadata with `node scripts/crypto-benchmark-info.mjs`.
2. Preserve its JSON beside exported samples.
3. Confirm the source tree is clean before building measured clients.
4. Use physical iPhone and Android devices with Release Hermes builds.
5. Disconnect debuggers and keep other workloads idle.
6. Run **Run crypto checks** before benchmarking.
7. Enter the model, OS version and exact source commit SHA in the benchmark form.
8. Enable **Physical phone** only on physical hardware.
9. Select **Run benchmark matrix**.
10. Export samples after completion, or stop and export partial results.
11. Preserve raw samples, metadata and gate reports under `docs/reference/crypto-benchmarks/YYYY-MM-DD-spike/`.

Exports use JSON files, avoiding Android's IPC limit for large text shares.
Combine both platform exports on the host:

```sh
pnpm exec tsx scripts/evaluate-crypto-benchmark.mjs ios.json android.json
```

The matrix contains 400 cells, with five rotated runs per backend and platform.
Each run records 100 warmups and 200 measured calls.
The complete matrix can take hours on Hermes. Partial data cannot pass the gate.
Repeated partial runs must not contain duplicate platform/backend/run/cell identifiers.

`wallMs` includes conversion, input snapshots, dispatch, computation and Promise settlement.
`jsMs` measures synchronous invocation time before the method returns its Promise.
It excludes result-delivery work and does not represent total JS CPU usage.
`timerDelayMs` records a zero-delay timer's observed latency during each operation.
`firstCall` records each cell's first invocation before warmups. The runtime is already initialised.
Neither provider caches public-key subgroup checks in this spike.

## Gate

Complete evidence requires both physical platforms, matching source revisions and valid timing rows.
Single calls remain separate from batches of one, eight, 32 and 128.
Every message size, verification workload, key distribution and blake3 output length contributes to the decision.

A route passes when every run improves median wall latency by at least 10% against strict noble.
Native p95 wall latency and p95 synchronous invocation time must remain no worse.
Timer delays provide responsiveness evidence. They are not CPU measurements.
Native profiling evidence remains necessary before claiming reduced total JS-thread occupation.

Incomplete evidence yields `pending`. Complete evidence without a passing route yields `stop`.
Only `proceed` permits the public API migration.
Native execution failures never trigger fallback.
