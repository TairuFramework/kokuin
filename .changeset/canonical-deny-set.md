---
"@kokuin/controller": patch
"@kokuin/capability": patch
---

Reject revoked peer:4 capability audiences regardless of long or short DID spelling. Return raw and canonical deny entries from controller resolvers and compare audience denials canonically, including third-party raw sets.
