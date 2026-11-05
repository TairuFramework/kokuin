---
"@kokuin/node": minor
---

Pass crypto through NodeKeyStoreParams for captured software identity signing. Reopening a cached service with a different resolved provider now rejects, including omission after custom selection.

All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
