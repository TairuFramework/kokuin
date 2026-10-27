# Complete physical crypto benchmark qualification

## Context

Standalone providers are implemented. Existing token, controller and records APIs retain their current behaviour.
The [completed delivery](../completed/2026-10-27-crypto-consumer-packages.complete.md) preserves the implemented scope.
The [Galaxy A35 probe](../../../reference/crypto-benchmarks/2026-10-27-android-probe/README.md) covers eight cells with reduced counts.
It found native curve improvements and native blake3 regressions for those workloads.
It does not satisfy the full performance gate.

## Work

1. Confirm access to physical Android and iPhone devices.
2. Estimate matrix duration from the actual Android probe before scheduling long runs.
3. Agree any statistically justified changes before reducing the current qualification requirements.
4. Build Release Hermes clients from one clean revision and capture exact versions and build flags.
5. Record device power policy, charging, thermal conditions and debugger state.
6. Collect current noble, strict noble and native samples for every retained workload.
7. Preserve raw samples, build metadata, profiler evidence and the resulting static routing manifest.
8. Repeat retained workloads against final distributions before the breaking API migration.

## Qualification rules

The current evaluator covers 400 cells on both physical platforms.
It requires 100 warmups and five rotated runs with at least 200 timings per backend and cell.
Messages span 0, 32, 256, 4096 and 65536 bytes.
Single calls remain distinct from batches of one, eight, 32 and 128.
Verification covers valid, invalid and mixed inputs with repeated and distinct keys.
blake3 output lengths cover 16, 32 and 64 bytes.

Strict noble supplies the pass/fail baseline. Current noble provides context for the existing verification policy.
Native median wall latency must improve by at least 10% in every run on both platforms.
Native p95 wall latency and synchronous invocation time must remain no worse.
Copying, marshalling, dispatch, cryptography and Promise settlement contribute to native wall latency.
Synchronous invocation time excludes result delivery. Native profiling is required before claiming reduced total JavaScript CPU occupation.

Missing evidence leaves the gate pending. Complete evidence with no winning route stops the migration.
Unmeasured or losing variants remain on documented noble routes. Native failures never cause fallback.
The reduced-count Android probe remains separate from qualification exports.

## Completion

Complete physical-platform evidence produces a reproducible report and an immutable route decision for every promoted variant.
No existing public API migration starts while the gate remains pending.
See [benchmark instructions](../../../reference/crypto-benchmark-spike.md) for execution and metric definitions.
