---
"@kokuin/token": minor
---

Add createKeyAgreementIdentityForDID: a DID-bound X25519 key-agreement identity that runs ECDH directly on a raw X25519 scalar (not a Montgomery-converted Ed25519 key), for did:kokuin: controllers whose agreement keypair is independent of the signing key.
