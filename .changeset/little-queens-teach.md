---
"@kokuin/store-controller": minor
---

Breaking: `createControllerStore(db, adapter, context)` takes the hozon store context. `merge` holds the key lock `('controller_logs', [did])`, so two merges for one DID on the same transaction no longer lose an update.
