---
"@kokuin/controller": minor
---

Export `deviceRevokeIndex` to find the first same-generation rotate newly denying a subject. Resets never count, and deny entries and the subject use canonical DID comparison, including equivalent `did:peer:4` long and short forms. Export `createDeviceRevoke` and `CreateDeviceRevokeParams` to build a rotate preserving the folded snapshot and adding one denial. An already-denied subject or invalid chain throws. Both helpers require a root-chain `icp` at index zero and only `rot` events afterwards.
