---
"@kokuin/store-vault": patch
---

Prevent vault record reads from deadlocking when issuer resolvers query the same SQLite provider.
