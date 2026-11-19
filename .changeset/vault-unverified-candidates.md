---
"@kokuin/store-vault": patch
---

Retain unverifiable entry and prior tombstone copies in candidate reads so repair callers can stay pending without hiding other candidates. Keep decision reads and stored-row integrity checks fail-closed.
