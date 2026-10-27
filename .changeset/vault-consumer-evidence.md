---
"@kokuin/store-vault": patch
---

Accept optional current-call `consumer` evidence on every coordinator mutation that signs records: `grant`, `rotate` and `repairFork` (key, branch, retained wrapping and revocation records), `setKeyState`, `deleteKey`, `addFactor`, `removeFactor`, the entry update methods, `deleteEntry` and `reKeyEntry`. Leaving it unset keeps the previous behaviour (inherit the prior record's evidence, else `null`); `null` clears it. Supplied evidence passes consumer metadata validation and authority before any write. `reendorse` keeps exact stored claims.
