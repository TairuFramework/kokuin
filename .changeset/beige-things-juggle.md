---
"@kokuin/controller": minor
---

Add provideControllerIdentity: a high-level utility that resolves a did:kokuin: FullIdentity (signing + decryption) from a keystore KeyEntry and a LogStore, generating on first use and restoring afterwards. Seed-based controller identities now return FullIdentity, and a didFor helper computes the DID without signing an inception.
