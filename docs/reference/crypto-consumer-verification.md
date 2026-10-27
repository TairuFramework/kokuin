# Crypto consumer package verification

**Date:** 2026-10-27
**Package implementation:** `2eeddba`
**Performance gate:** pending

Both public providers were packed at version 0.1.0 and installed into independent fixtures outside the monorepo.
The fixtures used tarballs rather than workspace links.
The private conformance suite was packed separately for the mobile test fixture.
No packages were published during this verification.

## Evidence

- The portable consumer signed the RFC 8032 empty-message vector and matched the official blake3 empty-input prefix.
- Its installed dependencies excluded Nitro, and Cargo was absent from its execution PATH.
- Packed native contents included both Android libraries, every iOS slice, generated glue, headers and licence notices.
- Packed manifests contained published dependency ranges rather than workspace, link or file references.
- Independent Android and iOS Release clients built with Cargo absent from PATH.
- Both clients passed shared conformance against noble and native providers through the Maestro completion marker.
- Each client ran 15 cases per provider, including caller-array resizing during native batch execution.
- Package tests rejected altered binaries, missing platform registration files and omitted licence notices.
- Factory tests rejected missing native registration and incompatible ABIs.
- Independent review found two material issues. Batch membership and complete generated-file validation now have regression coverage.
- All 92 repository tasks passed against the latest merged main using `pnpm test --concurrency=1`.

The initial parallel run stopped when Vitest processes collided while clearing their shared cache directory.
The serial run passed without product changes. Rust tests and native sanitizer checks also passed.

The iOS target was an iPhone 18 Pro simulator running iOS 27.0.
The Android target was the Pixel_9a emulator running Android API 36.
Both runtime targets were arm64. Cross-built libraries also covered x86_64 Android and arm64/x86_64 iOS simulators.

| Component | Version |
| --- | --- |
| pnpm | 12.15.0 |
| Rust | 1.99.1 |
| Xcode | 27.1 |
| Expo | 58.0.19 |
| React Native | 0.88.0 |
| Nitro | 0.37.1 |
| Public providers | 0.1.0 |

## Limits

These checks establish standalone installation and correctness. They do not establish physical-device performance improvements.
Existing token, controller and records APIs have not migrated to provider injection.
The expanded adversarial corpus and coordinated breaking release remain conditional rollout work.
The new cross-build and package workflow has not yet run remotely.
Portable runtime checks used Node. A fresh browser runtime check was not performed.

See [provider instructions](crypto-provider.md) for reproduction and installation.
