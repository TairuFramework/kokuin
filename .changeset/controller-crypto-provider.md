---
"@kokuin/controller": minor
---

Route controller signing and verification through immutable crypto providers. Signing, folding, history, log helpers and controller identity construction now return Promises. Isolate successful fold memos by provider and retain causal verification budgets. Default verification rejects signatures accepted only by ZIP-215.
