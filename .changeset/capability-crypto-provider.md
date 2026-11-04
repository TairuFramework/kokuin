---
"@kokuin/capability": minor
---

Add crypto to capability, delegation-chain and revocation options. Forward providers through parent and historic revocation verification. Default reverification rejects crafted ZIP-215-only signatures.

Use named params objects for public signatures and constructors. Export their named types. Preserve behaviour and update migration references.

`createCapability` takes `{ signer, payload, header?, options? }`.
