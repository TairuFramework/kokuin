---
"@kokuin/records": patch
---

`applyRecordChunk` reads every decision a chunk consults, each record's own and its dependencies', in one batched read under the chunk's locks, and keeps them updated with its own writes. Dependency checks and the new optional `RecordAuthorizeContext.decision` reader use this view, so a chunk no longer reads the store once per record and dependency. Each record's `dependencies` hook now runs once per chunk. Type hooks must not write record decisions.
