# @kokuin/node

## 0.2.0

### Minor Changes

- 7eec1ce: Fix keystore correctness issues around data loss, concurrency and unsafe defaults:

  - `BrowserKeyEntry` now resolves `setAsync` / `removeAsync` on transaction completion rather than on request success, so a write that is later aborted no longer reports success. `provideAsync` performs its get-or-generate inside a single IndexedDB transaction instead of two, closing a race where concurrent calls could each generate a key and the last write would win.
  - `NodeKeyEntry.provideAsync` serializes its get-or-generate within the process. A cross-process race on the OS keyring remains possible: `@napi-rs/keyring` exposes no compare-and-set. `NodeKeyStore.list()` no longer decodes credentials eagerly, so one corrupt entry cannot make the whole listing throw.
  - `ElectronKeyStore.open` accepts an `allowInsecureStorage` option (default `false`). Falling back to unencrypted storage when the OS keychain is unavailable is now opt-in, and reopening a cached store with a conflicting value throws instead of silently reusing the first one.
  - The store and entry caches use null-prototype objects, so a key ID such as `constructor` returns a real entry instead of a prototype member.

  BREAKING: `ElectronKeyStore` no longer falls back to unencrypted storage by default — pass `allowInsecureStorage: true` to `open()` to restore the old behavior. The third `NodeKeyEntry` constructor argument is now the base64-encoded key (`encoded?: string`) rather than the decoded bytes (`key?: Uint8Array`).

### Patch Changes

- Updated dependencies [bcfb386]
- Updated dependencies [1ecca02]
  - @kokuin/token@0.2.0
