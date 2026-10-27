---
"@kokuin/store-vault": minor
---

Add coordinator capabilities for consumers that keep their own authority policy:

- `refreshEntry` re-encrypts a stored entry at the current key version while preserving its authenticated content intent and public metadata, under entry, key and branch preconditions. It never inserts or resurrects an entry.
- `refreshWrapping` re-signs an existing live wrapping with newer evidence, keeping its ID, ciphertext, descriptors and recipient, without opening the key. It returns the accepted signed copy.
- `rotate({ sourceVersion })` rotates from a named older, openable version when current-version material is incomplete. Permanent revocations and exclusions still apply; a rotation that would retain no wrappings is refused.
- An optional `authorizeEquivalentBranch` port lets `readEntry` decrypt an entry on a losing branch when the consumer explicitly approves the authenticated branches. Without it, `VaultSupersededBranch` is unchanged.

Rotation now authenticates every supplied secret against the wrapping it recreates, so a wrong PIN can no longer silently change a retained PIN wrapping.
