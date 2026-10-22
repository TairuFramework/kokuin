---
"@kokuin/store-controller": minor
---

Controller logs are stored as `{ chain, events }` (breaking). `set` is removed; `merge(did, update)` reads and writes in one store transaction, atomic per DID (Postgres locks the row and reruns `update` after a lost first-insert race). Rows written in the old bare-array shape are read back as that chain with no epoch events. A legacy row whose chain holds a non-reset `rot` decodes but no longer folds (every rotate now carries a snapshot), so the resolver treats it as no memory: anti-truncation restarts from the next accepted log for those DIDs. A merge whose update hands back the stored log unchanged writes nothing, and a row that does not parse as JSON reads as no memory instead of throwing. Requires `@hozon/db` `^0.3.0` (was `^0.2.3`).
