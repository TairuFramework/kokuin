---
'@kokuin/token': minor
'@kokuin/browser': minor
'@kokuin/node': minor
'@kokuin/electron': minor
'@kokuin/expo': minor
'@kokuin/deterministic': minor
'@kokuin/ledger-device': patch
---

Faceted KeyStore/KeyEntry contract, reconciled across every backend.

**Breaking.** `KeyEntry` no longer has `setAsync`/`removeAsync` — they move to a new
`MutableKeyEntry`, so derived (HD) and identity-only (ledger) backends stop "conforming" by
throwing and no-op'ing. The free `provideFullIdentity`/`provideFullIdentityAsync` functions are
replaced by a `provideIdentity(keyID)` method on each store (the `IdentityProvider` contract),
with a `provideIdentitySync` twin where the substrate allows it.

- **token**: adds `MutableKeyEntry` and a framework-agnostic conformance suite
  (`keyStoreConformanceCases`) that every backend runs. Fixes `did:peer:4` identities being
  unencryptable-to (`createTokenEncrypter` threw `Invalid DID format` for every peer:4
  recipient, so the `keyAgreement` key published in the doc was unreachable), and `did:key`
  identities from `createIdentity` being unable to decrypt.
- **browser**: no longer mints ES256. Holds a non-extractable Ed25519 signing key plus the
  X25519 agreement key derived from it, yielding a `FullIdentity` with a `did:key` EdDSA DID.
  Existing ES256 records keep working, signing-only, via `provideSigningIdentity`; they are
  never silently re-keyed. Requires Chrome 137+, Firefox 130+, or Safari 17+ — it hard-errors
  rather than falling back, because a fallback would mint a different DID for the same keyID.
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
