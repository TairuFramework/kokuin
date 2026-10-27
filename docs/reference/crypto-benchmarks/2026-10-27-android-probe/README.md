# Galaxy A35 exploratory crypto probe

**Date:** 2026-10-27
**Device:** Samsung Galaxy A35 SM-A356B, Android 16, API 36, arm64
**Source revision:** `06faecb3cbe7ba2b94886bda956131334cdd308a`
**Gate:** pending

The physical phone passed all 15 shared conformance cases against both noble and native providers.
The timing probe then compared current noble, strict noble and native Rust in a Release Hermes consumer application.
The application used packed providers and required no Cargo during its native build.

Native signing and verification improved median and p95 wall latency for all six selected curve cells.
Native blake3 was slower for both selected cells.
These observations apply to this phone, workload and power policy.

## Workload and conditions

- Three rotated runs per backend and cell.
- Twenty warmup calls and fifty measured calls per run.
- Thirty-two-byte messages, valid signatures and repeated public keys.
- Single calls and batches of eight for Ed25519 signing, Ed25519 verification, ES256 verification and blake3.
- Thirty-two-byte blake3 output.
- Seventy-two timing rows and 3,600 measured API calls, with all raw timings preserved.

The run lasted from 17:51:43 to 18:03:07 UTC, approximately eleven minutes and twenty-four seconds.
Battery saver remained enabled. The phone remained connected to USB power.
No device power settings were changed.
Battery temperature measured 30.7°C when collection attached and 31.4°C after completion.
Collection attached after measurement began and recovered the complete result from the probe process's logs.

The package was not debuggable. No JavaScript debugger was attached by the probe runner.
Progress logging occurred between timing rows. Raw result export occurred after every measurement had finished.

## Wall latency

Values are milliseconds per API call, including the entire batch where applicable.
Medians and p95 values use nearest-rank percentiles pooled across 150 measurements per backend and cell.
Speed ratios compare native with strict noble, whose verification policy matches the native provider.

| Operation | Batch | Strict median | Native median | Native comparison |
| --- | --- | --- | --- | --- |
| Ed25519 sign | 1 | 12.386 | 1.910 | 6.48× faster |
| Ed25519 sign | 8 | 97.244 | 3.942 | 24.67× faster |
| Ed25519 verify | 1 | 99.610 | 3.033 | 32.85× faster |
| Ed25519 verify | 8 | 794.994 | 9.092 | 87.43× faster |
| ES256 verify | 1 | 80.302 | 5.569 | 14.42× faster |
| ES256 verify | 8 | 642.269 | 11.407 | 56.30× faster |
| blake3 | 1 | 0.469 | 2.136 | 4.56× slower |
| blake3 | 8 | 1.484 | 2.347 | 1.58× slower |

| Operation | Batch | Strict p95 | Native p95 |
| --- | --- | --- | --- |
| Ed25519 sign | 1 | 12.876 | 2.627 |
| Ed25519 sign | 8 | 99.451 | 4.378 |
| Ed25519 verify | 1 | 100.009 | 3.656 |
| Ed25519 verify | 8 | 796.076 | 10.378 |
| ES256 verify | 1 | 80.766 | 5.941 |
| ES256 verify | 8 | 644.686 | 13.038 |
| blake3 | 1 | 0.673 | 2.375 |
| blake3 | 8 | 1.838 | 2.655 |

`summary.json` and `summary.csv` include current noble and synchronous invocation timings as well.
Synchronous invocation timings exclude result-delivery work and do not measure total JavaScript CPU consumption.

## Evidence and reproduction

- [Raw samples and gate output](samples.json)
- [Device, dependency, binary and build metadata](metadata.json)
- [Probe parameters](profile.json)
- [Summary](summary.json) and [CSV](summary.csv)
- [Physical correctness result](correctness.txt)
- [ARM64-only package correctness](arm64-correctness.txt)
- [Archived entry point](ProbeApp.tsx.txt) and [benchmark profile patch](benchmark-profile.patch)

The entry point runs the shared conformance suite before timing.
It reuses the committed benchmark runner with only its repetition counts reduced through the archived patch.
Inputs, backend ordering, input copying and Promise timing use the original runner.

For reproduction, prepare the packed consumer fixture described in [provider instructions](../../crypto-provider.md).
Copy `benchmark.ts`, `gate.ts`, `spike.ts` and `strict-noble.ts` from the pinned revision into its `crypto` directory.
Apply the archived patch to the copied `benchmark.ts`.
Use the archived entry point as the fixture's `App.tsx`.
Update device and source metadata for a different setup.
Build Release Hermes and collect the numbered `KOKUIN_PROBE_CHUNK` messages from that application's process log.
Concatenating the chunks in numeric order reconstructs the raw JSON result.

## Build correction

An ARM64-only consumer build exposed a native package ABI-selection mismatch during probe preparation.
The native package always requested both supported ABIs while Nitro followed the application's requested subset.
The measured probe used the previously verified ARM64/x86_64 build.

The package now intersects supported ABIs with `reactNativeArchitectures` and rejects an entirely unsupported selection.
The corrected tarball built successfully for ARM64 alone and passed physical-phone conformance again.
The correction changes consumer build selection, rather than the cryptographic implementation measured here.

## Remaining gate work

This exploratory profile has fewer repetitions and samples than the full gate requires.
It covers eight of four hundred workload cells and contains no physical iOS evidence.
No production routing decision or existing public API migration is authorised by these results.

NOTE: keep these reduced-count samples separate from full gate exports. They cannot qualify a route.
The complete physical Android and iOS matrices remain necessary under the [benchmark instructions](../../crypto-benchmark-spike.md).
