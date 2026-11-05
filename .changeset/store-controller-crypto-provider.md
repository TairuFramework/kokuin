---
"@kokuin/store-controller": minor
---

Align exported controller contracts with asynchronous verification. Await authoritativeLog before returning its log from merge callbacks. Configure crypto on controller operations, rather than the SQL store.

All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
