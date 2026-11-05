# @kokuin/jwe

## 0.7.0

### Minor Changes

- Pass crypto through UnwrapOptions for signed-envelope verification, including both nested JWE/JWS modes. Default reverification is strict. Wrapping retains identity-owned signing.

  All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.

### Patch Changes

- Updated dependencies:
  - @kokuin/crypto@0.7.0
  - @kokuin/token@0.7.0

## 0.1.1

### Patch Changes

- Updated dependencies:
  - @kokuin/token@0.6.0

## 0.1.0

### Patch Changes

- Updated dependencies:
  - @kokuin/token@0.5.0
