---
"@kokuin/store-vault": minor
---

Rotation and fork repair no longer fail with `VaultNotFound` when a retained wrapping is addressed to another device's DID and also needs a secret factor, which the rotator cannot verify without that device's private key. By default `rotate` throws the new `VaultSecretUnverifiable` (with `wrappingID`, `recipientDID` and `factorKinds`) and `repairFork` returns `pending` with `reason: 'secret-unverifiable'`, both without writing. `RotateKeyParams.trustUnverifiableSecrets` opts in to re-wrapping such wrappings with the supplied secret inputs unverified; every secret the rotator can verify is still verified, exclusions and revocations still apply, and a missing input still refuses. A wrong trusted secret locks that recipient out of later versions until it recovers.
