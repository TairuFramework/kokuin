# @kokuin/crypto-napi

## 0.7.3

### Patch Changes

- Ship the prebuilt binaries in the platform packages. 0.7.2 published them empty, so `createNapiCrypto` fell back to `nodeCrypto` on every platform. Each platform package now fetches its attested binary in `prepublishOnly`, and publishing fails when it cannot.

- Updated dependencies:
  - @kokuin/crypto-napi-darwin-arm64@0.7.3
  - @kokuin/crypto-napi-darwin-x64@0.7.3
  - @kokuin/crypto-napi-linux-arm64-gnu@0.7.3
  - @kokuin/crypto-napi-linux-arm64-musl@0.7.3
  - @kokuin/crypto-napi-linux-x64-gnu@0.7.3
  - @kokuin/crypto-napi-linux-x64-musl@0.7.3
  - @kokuin/crypto-napi-win32-arm64-msvc@0.7.3
  - @kokuin/crypto-napi-win32-x64-msvc@0.7.3

## 0.7.2

### Patch Changes

- Install prebuilt binaries for linux x64 and arm64 (glibc and musl), macOS x64 and arm64, and Windows x64 and arm64 through `optionalDependencies`. `napiBindingPath()` now returns the installed package's binary when no local `native/` binary exists. Other platforms, and installs that omit optional dependencies, still use `nodeCrypto`.

- Updated dependencies:
  - @kokuin/crypto-napi-darwin-arm64@0.7.2
  - @kokuin/crypto-napi-darwin-x64@0.7.2
  - @kokuin/crypto-napi-linux-arm64-gnu@0.7.2
  - @kokuin/crypto-napi-linux-arm64-musl@0.7.2
  - @kokuin/crypto-napi-linux-x64-gnu@0.7.2
  - @kokuin/crypto-napi-linux-x64-musl@0.7.2
  - @kokuin/crypto-napi-win32-arm64-msvc@0.7.2
  - @kokuin/crypto-napi-win32-x64-msvc@0.7.2

## 0.7.1

### Patch Changes

- Fall back to `nodeCrypto` when a CJS bundle leaves the binary path unresolvable, instead of throwing from `createNapiCrypto()`. `NapiLoadFailure.path` is now optional.

## 0.7.0

### Minor Changes

- Use flat params objects for provider sign, signBatch, verify, blake3 and blake3Batch. Preserve behaviour and update migration references.

### Patch Changes

- Updated dependencies:
  - @kokuin/crypto@0.7.0
  - @kokuin/crypto-node@0.7.0
