---
"@kokuin/crypto-napi": patch
---

Fall back to `nodeCrypto` when a CJS bundle leaves the binary path unresolvable, instead of throwing from `createNapiCrypto()`. `NapiLoadFailure.path` is now optional.
