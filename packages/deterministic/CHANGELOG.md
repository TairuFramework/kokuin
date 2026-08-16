# @kokuin/deterministic

## 0.2.2

### Patch Changes

- Updated dependencies:
  - @kokuin/token@0.5.0

## 0.2.1

### Patch Changes

- Updated dependencies:
  - @kokuin/token@0.4.0

## 0.2.0

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

### Patch Changes

- Updated dependencies [84ecdaa]
  - @kokuin/token@0.3.0

## 0.1.2

### Patch Changes

- Updated dependencies [bcfb386]
- Updated dependencies [1ecca02]
  - @kokuin/token@0.2.0
