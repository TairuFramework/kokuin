# @kokuin/node

## Installation

```sh
npm install @kokuin/node
```

## Cross-process locking

`NodeKeyStore.open({ service, lockPath })` is opt-in. Without it, two processes racing to
generate a key for a fresh keyID both create one, and only the in-process lock applies — the
result is unsafe: silent key loss on backends that upsert unconditionally (e.g. Linux/
libsecret via `@napi-rs/keyring`), or a thrown duplicate-item error on macOS Keychain. With
`lockPath` set, `provideAsync()` serializes the create through a file lock (`@sozai/lock`) so
both processes converge on the same key.

`lockPath` must point to a **local** filesystem — `link()` is not atomic on NFS — and names a
file, not a directory: one coarse lock per store, not one per keyID. Acquisition is bounded and
throws on timeout rather than proceeding unlocked.

The synchronous `entry.provide()` cannot hold a cross-process lock (a file lock can't be
acquired synchronously), so it throws when the store was opened with a `lockPath`; use
`provideAsync()` instead.
