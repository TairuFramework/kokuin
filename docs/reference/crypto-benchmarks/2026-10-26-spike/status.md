# Mobile crypto spike verification

**Date:** 2026-10-26
**Gate:** pending

No physical-device performance measurements were collected.
Paul confirmed that physical phones are unavailable.
The native-versus-noble routing decision remains unmade. Existing public APIs and defaults remain unchanged.

## Verified behaviour

- Release app builds succeeded for iOS and Android.
- All three Maestro flows passed on each platform: `crypto-checks`, `sign-verify` and `two-identities`.
- Native checks cover all six operations, input-view snapshots, mixed verification results and retained output ownership.
- Strict checks reject identity-point and mixed-order Ed25519 forgeries on both backends.
- Rust core and C ABI tests passed.
- Native ownership and worker tests passed under AddressSanitizer and UndefinedBehaviorSanitizer.
- Worker tests cover real signing, partial-batch failure, dispatch failure and caller-thread rejection.
- The full pnpm test/type-check suite passed with 76 successful Turbo tasks.
- Artifact tests reject changed sources, modified binaries, missing binaries and source changes during compilation.
- Matching prebuilt artifacts passed preparation checks with Cargo absent from PATH.

Runtime targets were an iPhone 18 Pro simulator on iOS 27.0 and Pixel_9a emulator on Android API 36.
Both runtime targets were arm64. Other supported architectures were cross-built, rather than executed locally.

## Build environment

| Component | Version |
| --- | --- |
| Rust | 1.99.1 |
| Xcode | 27.1 |
| Android NDK | 27.1.12297006 |
| Expo | 58.0.17 |
| React Native | 0.88.0 |
| Nitro / Nitrogen | 0.37.1 |
| noble curves / hashes | 2.4.0 |
| ed25519-dalek | 3.0.0 |
| curve25519-dalek | 5.0.0 |
| p256 | 0.14.0 |
| blake3 | 1.8.7 |
| zeroize | 1.9.0 |

Native inputs use arrays of buffer views and synchronous copies before one worker dispatch per batch.
Private-key copies use zeroising owners. Returned buffers own Rust allocations until JavaScript releases them.
Build manifests record source fingerprints and binary hashes, preventing stale Rust libraries from qualifying as current artifacts.

## Toolchain setup update: 2026-10-27

pnpm 12.15.0 now installs Cargo dependencies, Rust 1.99.1, clippy, rustfmt, llvm-tools and all five mobile targets.
Native build scripts and the Rust host workflow use the pnpm-managed toolchain.
The separate rustup preparation step has been removed.
llvm-tools supplies the macOS shared library required by rust-objcopy without rustup's loader environment.

- Frozen installation and offline reinstallation passed without changing either lockfile.
- All nine Rust tests, formatting, clippy and native sanitizer checks passed.
- Forced Release recompilation passed for all five mobile targets without warnings.
- Both artifact manifests matched their source fingerprints and binary hashes.
- All 76 repository test tasks passed through Turbo's cache.

The updated GitHub workflow has not run remotely. Physical-device measurements remain pending.

## Remaining gate work

1. Capture clean-revision build metadata using `node scripts/crypto-benchmark-info.mjs`.
2. Build and run Release Hermes clients on physical iPhone and Android devices.
3. Collect the complete workload matrix without an attached debugger.
4. Export JSON files from both platforms.
5. Combine exports using `pnpm exec tsx scripts/evaluate-crypto-benchmark.mjs ios.json android.json`.
6. Preserve raw samples and the resulting report beside this verification record.

Simulator and emulator checks provide correctness evidence only. They do not satisfy the performance gate.
Full-size file export on physical devices and Linux mobile CI execution remain unverified locally.
The Rust host workflow and existing mobile workflows provide CI checks after this checkpoint is pushed.

See [benchmark instructions](../../crypto-benchmark-spike.md) for preparation, metric definitions and thresholds.
