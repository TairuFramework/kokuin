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
  the same reference. The bytes come from a module-private `WeakMap` populated at verification
  time, not from the token's own `data` property, which the mutating code could re-derive. Not
  reachable pre-auth: this operates on a token that has already passed signature verification.
- `assertDocWithinMaxSize` rejects a document whose `verificationMethod` array holds more entries
  than `maxSize` could ever fit, in O(1) before serializing it. Only that array is bounded early:
  any other array in the document is still caught by the serialized-size check, which pays a full
  `canonicalStringify` first. Reachable pre-auth: `resolveIssuerWithDoc` calls it while resolving
  `iss`, ahead of the signature check.
- `createInMemoryDIDCache().set` applies that same bound before encoding a resolver-supplied
  document. Not reachable pre-auth: the cache is only written after the `if (!verified) throw`.

`@kokuin/capability`: `createRevocationRecord`'s output is an audience-less payload, so a
`did:peer:4` grantor's revocation records now carry the long-form `iss` embed described above and
verify against a backend that has never seen the signer — with no source change in
`@kokuin/capability` itself.

This release also moves the `@sozai/codec` range to `^0.4.0`, which rejects non-canonical base64 by
default in `fromB64` and `fromB64U`. The spare bits in a base64 tail chunk — 4 for a one-byte tail,
2 for a two-byte tail — encode nothing and were previously ignored, so 16 distinct base64url strings
decoded to the same 64-byte Ed25519 signature; they must now be zero. That narrows what these entry
points accept: `verifyToken`, for both the header/payload segments it decodes through `b64uToJSON`
and the `signature` it decodes through `fromB64U`; `decryptToken`, for its protected header, `epk.x`,
`apu`, `apv`, IV, ciphertext and tag segments; and the re-exported `decodePrivateKey` (`fromB64`).
Every encoder in this stack emits canonical output, so anything round-tripped through `@kokuin/token`
is unaffected — a hand-written or third-party encoding with non-zero tail bits now throws
`Invalid base64 encoding` / `Invalid base64url encoding` where it used to decode. Padding is a
separate axis and is untouched: padded and unpadded spellings both still decode.

BREAKING: an existing `did:peer:4` signer now emits the long-form `iss` instead of the short form
whenever the signed payload has no single string `aud`. Pass `embedLongForm: false` to keep the
previous short-form `iss` on paths where recipients are known to already hold the document.
