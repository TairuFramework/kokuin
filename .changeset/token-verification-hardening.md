---
"@kokuin/token": minor
"@kokuin/capability": patch
---

Harden token verification against unsigned tokens, nullish input, and base58 decode denial of service:

- `verifyToken` now rejects `alg:none` tokens unless the caller passes `allowUnsigned: true`, and validates `exp` / `nbf` on the unsigned path when it does. Without the option its return type narrows to `VerifiedToken`, so a consumer cannot reach an unverified payload without an explicit opt-in.
- `isSignedToken`, `isUnsignedToken` and `isVerifiedToken` accept `unknown` and return `false` for nullish input instead of throwing `TypeError`.
- Bound every attacker-controlled base58 input before it reaches `@scure/base`'s O(n²) decode/encode, on all paths reachable before signature verification:
  - `did:peer:4` long form (`decodePeer4`): the default `maxDocSize` drops from 64 KiB to 4 KiB, the encoded pre-check uses the real base58 expansion ratio rather than an arbitrary `2x`, and the previously unbounded hash segment is capped.
  - `did:key` (`getSignatureInfo`): the payload is length-checked before decoding — it was decoded in full before any size check, reachable from `verifyToken` via the `iss` claim ahead of the signature check.
  - `did:peer:4` short form via a `resolver`: the resolver-returned document is size-bounded before it is re-encoded, and each `publicKeyMultibase` is length-checked before decoding.

BREAKING: `verifyToken` rejects `alg:none` tokens by default; pass `allowUnsigned: true` to restore the old behavior. Its return type is now `VerifiedToken<Payload>` rather than `Token<Payload>` unless `allowUnsigned` is set. The default `did:peer:4` document size limit is 4 KiB, down from 64 KiB.
