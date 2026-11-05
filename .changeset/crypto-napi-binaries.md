---
'@kokuin/crypto-napi': patch
---

Ship the prebuilt binaries in the platform packages. 0.7.2 published them empty, so `createNapiCrypto` fell back to `nodeCrypto` on every platform. Each platform package now fetches its attested binary in `prepublishOnly`, and publishing fails when it cannot.
