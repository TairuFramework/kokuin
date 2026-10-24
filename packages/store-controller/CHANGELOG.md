# @kokuin/store-controller

## 0.4.0

### Minor Changes

- Breaking: `createControllerStore(db, adapter, context)` takes the hozon store context. `merge` holds the key lock `('controller_logs', [did])`, so two merges for one DID on the same transaction no longer lose an update.

  Requires `@hozon/db` ^0.5.0 and `@hozon/adapter` ^0.2.1.

## 0.3.0

### Minor Changes

- Align with the breaking @hozon/db 0.4.0 and @hozon/adapter 0.2.0 releases.

- Updated dependencies:
  - @hozon/adapter@0.2.0
  - @hozon/db@0.4.0

## 0.2.0

### Minor Changes

- Controller logs are stored as `{ chain, events }` (breaking). `set` is removed; `merge(did, update)` reads and writes in one store transaction, atomic per DID (Postgres locks the row and reruns `update` after a lost first-insert race). Rows written in the old bare-array shape are read back as that chain with no epoch events. A legacy row whose chain holds a non-reset `rot` decodes but no longer folds (every rotate now carries a snapshot), so the resolver treats it as no memory: anti-truncation restarts from the next accepted log for those DIDs. A merge whose update hands back the stored log unchanged writes nothing, and a row that does not parse as JSON reads as no memory instead of throwing. Requires `@hozon/db` `^0.3.0` (was `^0.2.3`).

### Patch Changes

- Updated dependencies:
  - @kokuin/controller@0.2.0
