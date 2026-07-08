# Keystore correctness fixes

**Status:** complete
**Date:** 2026-07-07
**Origin:** `completed/2026-07-02-audit.complete.md` (Critical #4 + High/Medium keystore findings)
**Branch:** `fix/keystore-correctness` (16 commits)

## Goal

Fix six data-loss, concurrency, and safety bugs in the per-runtime keystores
(`@kokuin/electron`, `@kokuin/browser`, `@kokuin/node`) that could irrecoverably destroy an
identity. All were masked because every prior test used a fresh store per keyID. Scope was the
concrete bug fixes only; the KeyStore/KeyEntry **contract** spec and reconciling divergent
implementations remain a separate item (`next/2026-07-02-keystore-contract-and-adversarial-tests.md`),
kept apart because that work is API-design/reconciliation touching `@kokuin/token` and
`@kokuin/deterministic`, not mechanical correction.

## What was built

Six fixes, each TDD with a regression test that fails against the old code:

1. **electron `set()` clobber (Critical).** `set()` wrote the whole `keys` record with only its
   own entry, so storing a second identity deleted the first. Now reads-spread-writes like
   `remove()` already did.
2. **electron encryption gate (High).** On Linux without a keyring, `safeStorage` silently
   falls back to a hardcoded-key backend (plaintext-equivalent private keys). Writes now throw
   when `safeStorage.isEncryptionAvailable()` is false, unless the caller opts in via
   `ElectronKeyStore.open(name, { allowInsecureStorage: true })`. Reads still work to recover
   existing keys.
3. **browser resolve-before-commit (High).** `setAsync`/`removeAsync` resolved on
   `request.onsuccess`; a later transaction abort (e.g. quota) rolled back a write the promise
   had already reported as succeeded. Now resolve on `transaction.oncomplete`, reject on
   `onabort`/`onerror`.
4. **browser `provideAsync` race (High).** Was get-then-set in two transactions. Now generates
   the keypair first, then a single `readwrite` transaction does get-else-put. IndexedDB
   serializes readwrite transactions per object store, so this is atomic and safe across tabs.
   (A single transaction cannot span the async keypair generation — it would auto-close on the
   await — hence generate-first.)
5. **node `provideAsync` race (High).** The OS keyring exposes no compare-and-set
   (`@napi-rs/keyring` is get/set/delete only), so concurrency is closed with a per-entry
   in-process async mutex (a promise chain) serializing get→generate→set. A cross-**process**
   race remains unsolvable on the OS keyring and is documented inline. The store's per-keyID
   entry cache means one instance per keyID in normal use, so the per-instance lock holds.
6. **node `list()` eager decode (Medium).** `list()` decoded every credential up front, so one
   corrupt (non-base64) entry aborted the whole call. Decode is now deferred to first `get()`;
   the `NodeKeyEntry` constructor takes the raw encoded string instead of decoded bytes.
7. **prototype-cache collisions (Medium).** All entry and static open caches in all three
   packages were plain `{}` keyed by caller strings, so `entry('constructor')` /
   `open('__proto__')` returned `Object.prototype` members. All six caches now use
   `Object.create(null)`.

**Post-review follow-ups (also fixed on this branch):** electron `setAsync`/`provideAsync`
were made `async` so the encryption gate surfaces as a promise rejection rather than a
synchronous throw; `ElectronKeyStore.open()` now rejects a cached-name reuse that passes a
conflicting `allowInsecureStorage` flag (the singleton previously ignored options on a cache
hit — a security-relevant footgun).

## End-to-end coverage added

Because unit mocks cannot reach the real backends, e2e cases were added that each cross a real
reload/restart and assert on the persisted token issuer DID (`token.payload.iss`) — an
in-session key cache and store singleton otherwise mask clobber/durability bugs (the same trap
bit an early unit test, which passed pre-fix because the entry's in-memory key cache
short-circuited the storage read; fixed by reading back through a fresh store instance):

- **e2e-web** (playwright, real IndexedDB): identity durable across `page.reload()`; two
  identities coexist and both persist. Ran 9/9 across chromium/firefox/webkit locally.
- **e2e-electron** (playwright, real `electron-store`): two identities across a genuine app
  restart — proves the Critical clobber fix. Verified locally (Node 24, macOS) with real
  electron-forge packaging; the test fails against the pre-fix build and passes against the fix.
- **e2e-expo** (maestro, real SecureStore): two identities coexist. Verified by inspection +
  typecheck; runs on-device in CI (`e2e-android.yml`/`e2e-ios.yml`).

## Status

Complete. Unit suites green (electron 27, browser 26, node 26), biome clean. e2e-web verified
locally; e2e-electron verified locally with real packaging; e2e-expo runs in the CI device
matrix. No blocking issues from the whole-branch review.

## Key rule carried forward

Any test asserting electron/node keystore **storage** behavior must read back through a fresh
store instance (or a process restart) — the entry's in-memory `#key` cache short-circuits
`get()` and will otherwise hide storage-level bugs.
