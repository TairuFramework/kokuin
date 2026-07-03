# Keystore correctness fixes

**Status:** next
**Origin:** `completed/2026-07-02-audit.complete.md` (Critical #4, High: setAsync/race/electron, Medium: node list, proto cache)

## Context

The per-runtime keystores have data-loss and concurrency bugs that can irrecoverably
destroy an identity. Masked today because every test uses a fresh store per keyID. Fix
before any consumer stores more than one key.

## Work

### `ElectronKeyEntry.set()` destroys all other keys (Critical #4)

`packages/electron/src/entry.ts:58` does `setKeys({ [this.#keyID]: encrypted })`, replacing
the entire `keys` record (`store.ts:39` writes wholesale). Storing a second identity
deletes the first. `remove()` (`entry.ts:81`) does the read-spread-write correctly;
`set()` must too.

### Browser `setAsync` resolves before the transaction commits (High)

`packages/browser/src/entry.ts:28` resolves on `request.onsuccess`, not
`transaction.oncomplete`. A later abort (quota) rolls back a write the promise already
resolved — a fresh key handed out, DID published, key never persisted → unrecoverable
identity. Resolve on `oncomplete`, reject on `onabort`. Same pattern in `removeAsync`.

### Check-then-set race in `provideAsync` (High)

Browser (`entry.ts:36`, separate IDB transactions per `getStore()`) and node
(`entry.ts:67`, OS keyring) both do get-then-set without atomicity. Concurrent callers both
see null, both generate, the second `set` clobbers the first → orphaned key. Use a single
readwrite transaction, or `add()` + re-get on constraint error.

### electron: no `safeStorage.isEncryptionAvailable()` check (High)

`packages/electron/src/entry.ts:8`. On Linux without a keyring, Electron silently uses a
hardcoded-key backend → private keys plaintext-equivalent on disk, no warning. Check and
surface.

### Node `list()` eager-loads every private key (Medium)

`packages/node/src/store.ts:24` decodes all credentials; one corrupt (non-base64) entry
aborts the whole call. Defer decode to first `get()`.

### Prototype cache collisions (Medium)

node/browser stores use plain objects keyed by caller strings (`node/src/store.ts:44`,
`browser/src/store.ts:53`); `entry('constructor')` / `open('__proto__')` return prototype
members cast as entries. Use `Map` or `Object.create(null)`.

## Out of scope

- The KeyStore/KeyEntry *contract* spec and reconciling divergent implementations — see
  `next/2026-07-02-keystore-contract-and-adversarial-tests.md`. This item is the concrete
  bug fixes only.
