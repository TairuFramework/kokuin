---
"@kokuin/controller": minor
---

Await controller signing, verification, folding, branch resolution, history, log helpers and identity construction. Pass crypto through top-level params fields or builder parameters. Default reverification uses strict signatures.

Use named params objects for public signatures and constructors. Export their named types. Preserve behaviour and update migration references.

`deviceRevokeIndices` names its root-chain field `chain`, matching `deviceRevokeIndex`.

All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
