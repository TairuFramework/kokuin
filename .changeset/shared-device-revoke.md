---
"@kokuin/controller": minor
---

Export `deviceRevokeIndex` to find the first same-generation rotate newly denying a subject. Resets never count, and deny entries match exactly. Export `createDeviceRevoke` and `CreateDeviceRevokeParams` to build a rotate preserving the folded snapshot and adding one denial. An already-denied subject or invalid chain throws. Both helpers accept only root-chain `icp` and `rot` events.
