# @kokuin/capability

## 0.3.0

### Minor Changes

- Add createControllerCapabilityVerifier for authorising did:kokuin: revocations, enforcing historic mint and the profile deny set. Cap delegation-chain depth and require exp on device capabilities. Split the package into focused modules (types, patterns, time, token, delegation); the public API is unchanged through the barrel.

### Patch Changes

- Updated dependencies:
  - @kokuin/token@0.5.0

## 0.2.2

### Patch Changes

- **BREAKING:** a `did:peer:4` identity now embeds its long form in `iss` whenever the signed payload
  names no single string audience, where it previously emitted the short form. Pass
  `embedLongForm: false` to keep the short form on a broadcast path whose recipients are known to
  hold the document already.

  A short-form `did:peer:4` is a hash of the DID document and cannot be resolved without it, and the
  first-contact policy that embeds the long form was keyed on `payload.aud` — so an audience-less
  token was unverifiable by any recipient that had not already cached the signer's document.
  Revocation records and rotation assertions are both audience-less.

  **BREAKING:** the `@sozai/codec` range moves to `^0.4.0`, which rejects non-canonical base64 by
  default. The spare bits in a base64 tail chunk must now be zero, so 16 distinct base64url strings
  no longer decode to the same 64-byte Ed25519 signature. `verifyToken`, `decryptToken` and the
  re-exported `decodePrivateKey` now throw `Invalid base64 encoding` / `Invalid base64url encoding`
  on inputs they used to accept. Every encoder in this stack emits canonical output, so anything
  round-tripped through `@kokuin/token` is unaffected. Padding is untouched: padded and unpadded
  spellings both still decode.

  `@kokuin/capability`: `createRevocationRecord`'s output is an audience-less payload, so a
  `did:peer:4` grantor's revocation records now carry the long-form `iss` embed and verify against a
  backend that has never seen the signer — with no source change in `@kokuin/capability` itself.

  Also hardened, with no API change: `verifyToken` re-binds an already-verified token's payload to
  its signed bytes rather than trusting object identity, and oversized DID documents are rejected
  before serialization — both on resolution and in `createInMemoryDIDCache().set`.

- Updated dependencies:
  - @kokuin/token@0.4.0

## 0.2.1

### Patch Changes

- Updated dependencies [84ecdaa]
  - @kokuin/token@0.3.0

## 0.2.0

### Minor Changes

- bcfb386: Harden the capability/token authorization model:

  - Reject permission prefix escalation in `hasPartsMatch` — a grant more specific than the request no longer authorizes the broader request, and there is no implicit descent (use a trailing `*`).
  - Enforce the `authentication` relationship when an explicit `kid` is present, so a key listed only under `assertionMethod` cannot sign tokens.
  - Add an `audience` option to `verifyToken` that validates the invocation token's `aud` (and rejects unsigned/`alg:none` tokens when set).
  - Sign revocation records so only a token's own issuer can revoke it; the checker re-verifies the record signature on use.

  BREAKING: `RevocationBackend.isRevoked(jti)` is replaced by `get(jti)`, and `RevocationRecord` is now a signed token (`SignedToken<RevocationClaims>`) rather than a plain object.

### Patch Changes

- 1ecca02: Harden token verification against unsigned tokens, nullish input, and base58 decode denial of service:

  - `verifyToken` now rejects `alg:none` tokens unless the caller passes `allowUnsigned: true`, and validates `exp` / `nbf` on the unsigned path when it does. Without the option its return type narrows to `VerifiedToken`, so a consumer cannot reach an unverified payload without an explicit opt-in.
  - `isSignedToken`, `isUnsignedToken` and `isVerifiedToken` accept `unknown` and return `false` for nullish input instead of throwing `TypeError`.
  - Bound every attacker-controlled base58 input before it reaches `@scure/base`'s O(n²) decode/encode, on all paths reachable before signature verification:
    - `did:peer:4` long form (`decodePeer4`): the default `maxDocSize` drops from 64 KiB to 4 KiB, the encoded pre-check uses the real base58 expansion ratio rather than an arbitrary `2x`, and the previously unbounded hash segment is capped.
    - `did:key` (`getSignatureInfo`): the payload is length-checked before decoding — it was decoded in full before any size check, reachable from `verifyToken` via the `iss` claim ahead of the signature check.
    - `did:peer:4` short form via a `resolver`: the resolver-returned document is size-bounded before it is re-encoded, and each `publicKeyMultibase` is length-checked before decoding.

  BREAKING: `verifyToken` rejects `alg:none` tokens by default; pass `allowUnsigned: true` to restore the old behavior. Its return type is now `VerifiedToken<Payload>` rather than `Token<Payload>` unless `allowUnsigned` is set. The default `did:peer:4` document size limit is 4 KiB, down from 64 KiB.

- Updated dependencies [bcfb386]
- Updated dependencies [1ecca02]
  - @kokuin/token@0.2.0
