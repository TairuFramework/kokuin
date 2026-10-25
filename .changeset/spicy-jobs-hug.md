---
"@kokuin/token": patch
---

Cooperative yields: the default verifiers await `maybeYield()` from `@sozai/async` before the curve math on a memo miss (a hit stays synchronous and never yields), and both `signToken` implementations await it before `ed25519.sign`, so a run of signs or verifies lets timers, I/O and rendering in between. Default verifiers returned by `getVerifier` now answer a miss with a promise. Caller-supplied `verifiers` are called as given, without a yield. Adds a dependency on `@sozai/async` ^0.4.2.
