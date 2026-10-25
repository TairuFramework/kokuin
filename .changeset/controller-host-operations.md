---
"@kokuin/store-controller": patch
---

Add `getForUpdate` for controller log reads that hold merge's DID lock through the host transaction, including absent DIDs. Add `markObserved` to refresh observation time without rewriting the stored log or signalling a content change. Observation refreshes join host transactions and do nothing for unknown DIDs.
