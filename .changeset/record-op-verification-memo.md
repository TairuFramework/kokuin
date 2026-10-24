---
"@kokuin/records": patch
---

`verifyRecordOp` keeps a bounded, process-wide memo of verified ops (`RECORD_OP_MEMO_SIZE`, least recently used evicted first), keyed by op kind and op hash. Only self-certifying issuers (`did:key`, `did:peer:4` with no registry entry for the method) are kept, and only successes; every caller gets its own copy. New `createRecordVerifier` verifies each distinct token once for its lifetime, whatever the issuer; `applyRecordChunk` scopes one to each call. `filterVisibleRecords` lists key holdings once per call and checks each holding at most once, and reads each key version once.
