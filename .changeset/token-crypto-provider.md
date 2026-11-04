---
"@kokuin/token": minor
---

Pass crypto through identity and verification options. Identities capture signing providers and verification caches isolate policies. Default reverification rejects crafted ZIP-215-only signatures without a historical rescan or version gate.

Coalesce concurrent cold token verifications per provider across algorithms into verifyBatch calls. Preserve single verification calls for lone misses and success-only provider-isolated memoisation.
