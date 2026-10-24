# @kokuin/store-delegation

## 0.3.0

### Minor Changes

- Breaking: `createDelegationStore(db, adapter, context)` takes the hozon store context, and `0-init` is rewritten (primary key `(grantor, audience, resource, jti)`, `superseded` column, partial unique index on the active key; reset the database). A losing or replaced grant is kept as superseded so a delivered JTI stays revocable; active reads filter superseded rows, JTI lookups include them. Arbitration is serialised per logical key, also within one transaction. New `listUnrevokedSupersededTokens`.

  Requires `@hozon/db` ^0.5.0 and `@hozon/adapter` ^0.2.1.

## 0.2.0

### Minor Changes

- Align with the breaking @hozon/db 0.4.0 and @hozon/adapter 0.2.0 releases.

- Updated dependencies:
  - @hozon/adapter@0.2.0
  - @hozon/db@0.4.0

## 0.1.1

### Patch Changes

- Requires `@hozon/db` `^0.3.0` (was `^0.2.3`).

- Updated dependencies:
  - @kokuin/capability@0.5.0
  - @kokuin/token@0.6.0
