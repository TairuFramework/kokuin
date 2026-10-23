---
"@kokuin/controller": patch
---

Add `deviceRevokeIndices(did, chain, subject)`: every same-generation rotate that newly denies the subject, folded once. A verifier checking a specific rotate, or applying its own generation floor, uses it instead of the first index, so a re-revoke after a reset is found.
