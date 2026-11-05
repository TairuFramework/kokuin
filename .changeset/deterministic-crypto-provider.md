---
"@kokuin/deterministic": minor
---

Pass crypto alongside basePath to seed and mnemonic factories, or through HDKeyStoreParams. Factories remain synchronous and returned identities capture the software signing provider.

All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
