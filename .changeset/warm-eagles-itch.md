---
"@kokuin/capability": minor
---

The capability-authorised `did:kokuin:` revoke is removed (breaking): `createControllerCapabilityVerifier`, `assertRevokeCapabilityAudience`, the `CapabilityAuthorisation` / `ControllerCapabilityVerifier` / `ControllerCapabilityVerifierParams` types and the `REVOKE_*` reason constants are gone. Management authority now lives in the `did:kokuin:` log as management members (`@kokuin/controller`). `audienceConfirmation` stays.
