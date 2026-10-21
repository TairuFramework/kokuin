---
"@kokuin/store-controller": minor
---

Controller logs are stored as `{ chain, events }` (breaking). `set` is removed; `merge(did, update)` reads and writes in one store transaction, atomic per DID (Postgres locks the row and reruns `update` after a lost first-insert race). Rows written in the old bare-array shape are read back as that chain with no epoch events.
