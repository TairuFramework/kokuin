---
"@kokuin/crypto": patch
---

Cache strict Ed25519 public-key validation by encoded bytes in a bounded 256-entry cache. Preserve small-order and torsion-free checks for public keys and every signature point.
