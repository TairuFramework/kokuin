---
"@kokuin/vault": minor
---

Make decodeVaultRecord asynchronous and await record payload validation before decoding or authorising content. Compare authenticated branches using carried content digests.

Make vault digests, key IDs, key references and metadata validation asynchronous. Route hashing and record validation through the selected crypto provider while preserving canonical bytes and synchronous branch comparisons.
