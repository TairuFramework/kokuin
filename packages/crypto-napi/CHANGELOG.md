# @kokuin/crypto-napi

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
