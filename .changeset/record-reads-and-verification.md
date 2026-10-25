---
"@kokuin/records": minor
---

Fewer store reads and signature verifications in record apply, reads and visibility, and independent work run together. New restrictions:

- **Type hooks must not write record decisions.** `applyRecordChunk` reads every decision a chunk consults, each record's own and its dependencies', in one batched read under the chunk's locks, and keeps that view updated with its own writes. A hook that writes decisions directly is not seen by the rest of the chunk.
- **`RecordStoreAdapter.get` must accept concurrent calls**, including on an adapter bound to a transaction. Without `getMany`, `getRecordDecisions` and apply issue several `get` calls at once.
- **`resolveController` and visibility hooks must accept concurrent calls.** Apply resolves a chunk's controller DIDs at once before its locks. `filterVisibleRecords` runs the `visibleTo` hooks, and the context's resolvers and store, for all its records at once. At most 16 such calls run at once (`CONCURRENCY_LIMIT`), as for the `get` fallback in `getRecordDecisions`, so a large page cannot fill a connection pool. Errors still surface as the first failure in record order. `lockKeys`, `precheck` and the other type hooks are still called one at a time.

Changes:

- `applyRecordChunk` no longer reads the store once per record and dependency. Dependency checks and the new optional `RecordAuthorizeContext.decision` reader use the chunk's view. Each record's `dependencies` hook runs once per chunk.
- `getRecordDecisions` runs its `get` fallback concurrently for stores without `getMany`. Every read settles, then the first failure in key order is thrown. The result map is unchanged.
- `verifyRecordOp` keeps a bounded, process-wide memo of verified ops (`RECORD_OP_MEMO_SIZE`, least recently used evicted first), keyed by op kind and op hash. Only self-certifying issuers (`did:key`, `did:peer:4` with no registry entry for the method) are kept, and only successes. Every caller gets its own copy.
- New `createRecordVerifier` verifies each distinct token once for its lifetime, whatever the issuer. `applyRecordChunk` uses one before taking its locks and a fresh one inside its transaction, so a key removal committed before the locks is seen.
- `filterVisibleRecords` lists key holdings once per call, checks each holding at most once, and reads each key version once. A holding's stored row and its dependencies are read in one batch.
- Apply verifies the signatures of a chunk's records together, after their clock and type checks; prechecks still run in record order.
- `signRecordOp` calls each `SigningIdentity` object one at a time, in call order, so a hardware or prompting signer never sees overlapping calls. The queue is per object: two objects for one key are not serialised against each other. `signToken` must settle, since a call that never settles holds every later call for that object.
