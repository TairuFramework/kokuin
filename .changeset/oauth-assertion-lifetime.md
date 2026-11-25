---
"@kokuin/oauth": patch
---

`createClientAssertion` throws when `lifetimeSeconds` is not a positive integer, instead of signing an assertion that is already expired or has a malformed `exp`.
