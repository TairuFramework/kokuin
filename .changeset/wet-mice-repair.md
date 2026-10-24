---
"@kokuin/store-delegation": minor
---

Breaking: `createDelegationStore(db, adapter, context)` takes the hozon store context, and `0-init` is rewritten (primary key `(grantor, audience, resource, jti)`, `superseded` column, partial unique index on the active key; reset the database). A losing or replaced grant is kept as superseded so a delivered JTI stays revocable; active reads filter superseded rows, JTI lookups include them. Arbitration is serialised per logical key, also within one transaction. New `listUnrevokedSupersededTokens`.

Requires `@hozon/db` ^0.5.0 and `@hozon/adapter` ^0.2.1.
