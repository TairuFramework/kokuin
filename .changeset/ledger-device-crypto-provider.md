---
"@kokuin/ledger-device": minor
---

Use named params objects for public signatures and constructors. Export their named types. Preserve behaviour and update migration references.

All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
