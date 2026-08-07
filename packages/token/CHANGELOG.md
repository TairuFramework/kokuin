# @kokuin/token

## 0.4.0

### Minor Changes

- New `deriveSharedSecret(did)` performs X25519 key agreement with a recipient DID directly, without
  building a JWE to carry a secret the recipient could have derived.

  It generates the ephemeral key pair internally and returns `{ sharedSecret, ephemeralPublicKey }`.
  The recipient recovers the identical bytes with the existing `identity.agreeKey(ephemeralPublicKey)`.

  ```ts
  const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(recipientDID)
  // recipient, unchanged API:
  const recovered = await identity.agreeKey(ephemeralPublicKey)
  ```

  `sharedSecret` is the raw ECDH output, not a key — it is not uniformly random, so run it through a
  KDF with your own domain separation before use.

  Recipient DIDs are resolved exactly as `createTokenEncrypter` already resolves them, with the same
  errors: a `did:peer:4` short form is refused, as is a long form publishing no usable X25519
  `keyAgreement` entry, as is any non-EdDSA `did:key`.

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

## 0.3.0

### Minor Changes

- 84ecdaa: Faceted KeyStore/KeyEntry contract, reconciled across every backend.

  **Breaking.** `KeyEntry` no longer has `setAsync`/`removeAsync` — they move to a new
  `MutableKeyEntry`, so derived (HD) and identity-only (ledger) backends stop "conforming" by
  throwing and no-op'ing. The free `provideFullIdentity`/`provideFullIdentityAsync` functions are
  replaced by a `provideIdentity(keyID)` method on each store (the `IdentityProvider` contract),
  with a `provideIdentitySync` twin where the substrate allows it.

  Every store's `open()` / constructor and every `KeyEntry` constructor now takes a **single
  params object** rather than positional arguments — `NodeKeyStore.open({ service, lockPath })`,
  `ElectronKeyStore.open({ name, allowInsecureStorage, lockPath })`,
  `BrowserKeyStore.open({ name })` — matching the shape `deterministic` already used
  (`HDKeyStore.fromSeed`/`fromMnemonic` keep their name-paired positional primary).

  - **token**: adds the `MutableKeyEntry` / `KeyStore` / `IdentityProvider` contract. The
    framework-agnostic conformance suite every backend runs lives in the private
    `@kokuin/keystore-conformance` package (not published — it is test-only). Fixes `did:peer:4`
    identities being unencryptable-to (`createTokenEncrypter` threw `Invalid DID format` for every
    peer:4 recipient, so the `keyAgreement` key published in the doc was unreachable), and
    `did:key` identities from `createIdentity` being unable to decrypt.
  - **browser**: no longer mints ES256. Holds a non-extractable Ed25519 signing key plus the
    X25519 agreement key derived from it, yielding a `FullIdentity` with a `did:key` EdDSA DID.
    Existing ES256 records keep working, signing-only, via `provideSigningIdentity`; they are
    never silently re-keyed. Requires Chrome 137+, Firefox 130+, or Safari 17+ — it hard-errors
    rather than falling back, because a fallback would mint a different DID for the same keyID.
    The X25519 agreement key is stored as raw bytes rather than a non-extractable `CryptoKey`,
    because WebKit cannot persist an X25519 `CryptoKey` in IndexedDB
    (https://bugs.webkit.org/show_bug.cgi?id=312279) — without this, Safari minted a new identity
    on every reload. The signing key stays non-extractable. This is a tracked interim workaround.
  - **node**, **electron**: `PrivateKeyType` is `Uint8Array` in both (electron was base64
    `string`). Both gain an opt-in `lockPath` that closes the cross-process race on a fresh
    keyID: two processes both generate a key, and without the lock the result is unsafe — silent
    key loss on backends that upsert (Linux/libsecret), or a thrown duplicate-item error on macOS
    Keychain. `lockPath` (via `@sozai/lock`) serializes the create so both converge on one key.
    Electron also gains the prototype-pollution guard it lacked.
  - **expo**: `ExpoKeyStore` becomes a class with a cached `entry()` and a `provideAsync` lock.
    Its `entry()` no longer takes an undeclared second argument — options move to construction.
  - **deterministic**: `entry(x).keyID` now returns `x` rather than the derivation path (exposed
    separately as `path`). Non-hardened derivation paths throw.

## 0.2.0

### Minor Changes

- bcfb386: Harden the capability/token authorization model:

  - Reject permission prefix escalation in `hasPartsMatch` — a grant more specific than the request no longer authorizes the broader request, and there is no implicit descent (use a trailing `*`).
  - Enforce the `authentication` relationship when an explicit `kid` is present, so a key listed only under `assertionMethod` cannot sign tokens.
  - Add an `audience` option to `verifyToken` that validates the invocation token's `aud` (and rejects unsigned/`alg:none` tokens when set).
  - Sign revocation records so only a token's own issuer can revoke it; the checker re-verifies the record signature on use.

  BREAKING: `RevocationBackend.isRevoked(jti)` is replaced by `get(jti)`, and `RevocationRecord` is now a signed token (`SignedToken<RevocationClaims>`) rather than a plain object.

- 1ecca02: Harden token verification against unsigned tokens, nullish input, and base58 decode denial of service:

  - `verifyToken` now rejects `alg:none` tokens unless the caller passes `allowUnsigned: true`, and validates `exp` / `nbf` on the unsigned path when it does. Without the option its return type narrows to `VerifiedToken`, so a consumer cannot reach an unverified payload without an explicit opt-in.
  - `isSignedToken`, `isUnsignedToken` and `isVerifiedToken` accept `unknown` and return `false` for nullish input instead of throwing `TypeError`.
  - Bound every attacker-controlled base58 input before it reaches `@scure/base`'s O(n²) decode/encode, on all paths reachable before signature verification:
    - `did:peer:4` long form (`decodePeer4`): the default `maxDocSize` drops from 64 KiB to 4 KiB, the encoded pre-check uses the real base58 expansion ratio rather than an arbitrary `2x`, and the previously unbounded hash segment is capped.
    - `did:key` (`getSignatureInfo`): the payload is length-checked before decoding — it was decoded in full before any size check, reachable from `verifyToken` via the `iss` claim ahead of the signature check.
    - `did:peer:4` short form via a `resolver`: the resolver-returned document is size-bounded before it is re-encoded, and each `publicKeyMultibase` is length-checked before decoding.

  BREAKING: `verifyToken` rejects `alg:none` tokens by default; pass `allowUnsigned: true` to restore the old behavior. Its return type is now `VerifiedToken<Payload>` rather than `Token<Payload>` unless `allowUnsigned` is set. The default `did:peer:4` document size limit is 4 KiB, down from 64 KiB.
