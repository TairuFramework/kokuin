---
'@kokuin/token': minor
'@kokuin/capability': patch
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

Also hardened:

- `verifyToken` re-binds an already-verified token's payload to its signed bytes instead of
  trusting object identity alone, so in-process code cannot mutate a verified payload and re-submit
  the same reference. Not reachable pre-auth: this operates on a token that has already passed
  signature verification.
- `assertDocWithinMaxSize` rejects on `verificationMethod` entry count in O(1) before serializing
  an attacker-supplied document. Reachable pre-auth: `resolveIssuerWithDoc` calls it while resolving
  `iss`, ahead of the signature check.
- `createInMemoryDIDCache().set` applies that same bound before encoding a resolver-supplied
  document. Not reachable pre-auth: the cache is only written after the `if (!verified) throw`.

`@kokuin/capability`: `createRevocationRecord`'s output is an audience-less payload, so a
`did:peer:4` grantor's revocation records now carry the long-form `iss` embed described above and
verify against a backend that has never seen the signer — with no source change in
`@kokuin/capability` itself.

BREAKING: an existing `did:peer:4` signer now emits the long-form `iss` instead of the short form
whenever the signed payload has no single string `aud`. Pass `embedLongForm: false` to keep the
previous short-form `iss` on paths where recipients are known to already hold the document.
