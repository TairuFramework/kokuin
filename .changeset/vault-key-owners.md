---
"@kokuin/store-vault": patch
---

Add `VaultStoreAPI.listKeyOwners(keyID)`, the key counterpart of `listEntryOwners`: it returns the owner DIDs holding a live key row with that ID, in local and replicated mode, in deterministic order, joining the caller's transaction. Results are candidates only; callers verify each one against the key ID and run their own authority checks.
