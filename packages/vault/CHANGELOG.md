# @kokuin/vault

## 0.7.0

### Minor Changes

- Await digest helpers, key IDs, key references, metadata validation, decoding and descriptor checks. Pass crypto through top-level params fields, record-type parameters and wrapping parameters. Branch comparisons remain synchronous.

  Use named params objects for public signatures and constructors. Export their named types. Preserve behaviour and update migration references.

  All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.

### Patch Changes

- Updated dependencies:
  - @kokuin/crypto@0.7.0
  - @kokuin/jwe@0.7.0
  - @kokuin/records@0.7.0
  - @kokuin/token@0.7.0

## 0.1.0

### Patch Changes

- Updated dependencies:
  - @kokuin/records@0.2.0
