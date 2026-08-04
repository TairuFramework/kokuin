---
'@kokuin/token': minor
---

A `did:peer:4` identity now embeds its long form in `iss` whenever the signed payload names no
single string audience.

A short-form `did:peer:4` is a hash of the DID document and cannot be resolved without it, and the
first-contact policy that embeds the long form is keyed on `payload.aud` — so an audience-less token
was unverifiable by any recipient that had not already cached the signer's document. Revocation
records (`@kokuin/capability`) and rotation assertions are both audience-less, so neither bound
anywhere but on the signer's own device.

Pass `embedLongForm: false` to keep the short form on a broadcast path whose recipients are known
to hold the document already.

Also hardened, none of it remotely reachable pre-auth:

- `verifyToken` re-binds an already-verified token's payload to its signed bytes instead of
  trusting object identity alone, so in-process code cannot mutate a verified payload and re-submit
  the same reference.
- `assertDocWithinMaxSize` rejects on `verificationMethod` entry count in O(1) before serializing
  an attacker-supplied document.
- `createInMemoryDIDCache().set` applies that same bound before encoding a resolver-supplied
  document.
