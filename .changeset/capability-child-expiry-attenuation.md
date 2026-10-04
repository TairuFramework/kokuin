---
'@kokuin/capability': patch
---

Reject delegated capabilities whose expiry exceeds their parent's expiry or is absent when the parent has an expiry. Apply the same attenuation when minting and verifying every capability link, while preserving unbounded parents and invocation behaviour.
