---
"@kokuin/capability": minor
---

Add an optional `yield: false` policy to capability and delegation-chain verification, forwarding it through every verified chain link. Forward the policy to verification hooks and revocation record verification, and support it during capability creation for parent verification and signing. Default yielding behaviour is unchanged.
