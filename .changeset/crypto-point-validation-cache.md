---
"@kokuin/crypto": patch
---

Cache strict Ed25519 public-key validation by encoded bytes in a bounded 256-entry cache. Preserve small-order and torsion-free checks for public keys and every signature point.

All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
