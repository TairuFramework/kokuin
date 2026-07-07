# Keystore correctness fixes — design

**Date:** 2026-07-07
**Origin:** `docs/agents/plans/next/2026-07-02-keystore-correctness-fixes.md`
(from `completed/2026-07-02-audit.complete.md`, Critical #4 + High/Medium keystore findings)

## Problem

The per-runtime keystores (`@kokuin/electron`, `@kokuin/browser`, `@kokuin/node`) have
data-loss, concurrency, and safety bugs that can irrecoverably destroy an identity. All are
masked today because every existing test uses a fresh store per keyID. Fix before any
consumer stores more than one key.

The KeyStore/KeyEntry *contract* spec and reconciling divergent implementations are **out of
scope** — tracked separately in
`next/2026-07-02-keystore-contract-and-adversarial-tests.md`. This design is the concrete bug
fixes only.

## Approach

TDD each fix: a regression test that reproduces the bug first, then the fix. Tests use vitest
per package following existing patterns; concurrency is exercised with `Promise.all` on a
single shared entry.

## Fixes

### 1. Electron `set()` destroys all other keys (Critical)

`packages/electron/src/entry.ts:56` does `setKeys({ [this.#keyID]: encrypted })`. Because
`store.ts:39` writes the `keys` record wholesale, storing a second identity deletes the first.
`remove()` (`entry.ts:80`) already does the correct read-spread-write.

**Fix:** `set()` reads the current keys, sets its own field, writes the merged record:

```
set(key) {
  const keys = this.#storage.getKeys()
  keys[this.#keyID] = encryptKey(key)
  this.#storage.setKeys(keys)
  this.#key = key
}
```

**Test:** store key A, store key B on a second entry, assert A still readable.

### 2. Browser `setAsync`/`removeAsync` resolve before the transaction commits (High)

`packages/browser/src/entry.ts:28` (and `:46`) resolve on `request.onsuccess`, not
`transaction.oncomplete`. A later abort (e.g. quota) rolls back a write the promise already
resolved as succeeded → a fresh key handed out and a DID published for a key never persisted →
unrecoverable identity.

**Fix:** capture the transaction from the `getStore('readwrite')` call, resolve on
`transaction.oncomplete`, reject on `transaction.onabort` / `transaction.onerror`. Apply to
both `setAsync` and `removeAsync`.

**Test:** wire-level assertion that resolution is tied to `oncomplete` (via a fake IDB store
whose request succeeds but whose transaction has not yet completed). This is the one test with
reduced fidelity — forcing a real post-success abort deterministically is impractical; the
test covers the wiring, not a live quota abort.

### 3. Check-then-set race in `provideAsync` (High)

Concurrent callers both observe `null`, both generate, the second `set` clobbers the first →
orphaned key.

- **Browser** (`entry.ts:36`): a single `readwrite` transaction cannot span the async
  `randomKeyPair()` (an IDB transaction auto-closes on the next microtask with no pending
  request, i.e. across an `await`). Instead: **generate the keypair first**, then run one
  `readwrite` transaction that does `get` → if a value is present return it (discarding the
  freshly generated pair), else `put` the generated pair. IDB serializes `readwrite`
  transactions on the same object store, so this is atomic and also safe across tabs of the
  same origin.
- **Node** (`entry.ts:77`): the OS keyring exposes no transaction or compare-and-set
  (`@napi-rs/keyring` is get/set/delete only). Serialize `get → generate → set` with a
  per-`keyID` in-process async mutex (a promise chain held on the entry). This closes the
  common single-process race. A **cross-process** race remains unsolvable on the OS keyring
  and is documented with an inline code comment.

**Test:** fire N concurrent `provideAsync` calls on one entry, assert every result equals the
same key.

### 4. Electron: no `safeStorage.isEncryptionAvailable()` check (High)

`packages/electron/src/entry.ts`. On Linux without a keyring, Electron `safeStorage` silently
falls back to a hardcoded-key backend, leaving private keys plaintext-equivalent on disk with
no warning.

**Fix:** `ElectronKeyStore.open(name, options?)` accepts `allowInsecureStorage?: boolean`
(default `false`), threaded through to the entries. On any write (`set` / `provide` / their
async forms), if `safeStorage.isEncryptionAvailable()` is `false` and `allowInsecureStorage`
is not set, throw an error whose message names the missing-Linux-keyring cause and the opt-in
flag. Reads still work so an existing key can be recovered. The opt-in exists for dev/CI.

**Test:** mock `safeStorage` as unavailable; assert `set` throws; assert `allowInsecureStorage:
true` bypasses the throw.

### 5. Node `list()` eager-loads every private key (Medium)

`packages/node/src/store.ts:24` (`#toEntry`) decodes every credential's password up front, so
one corrupt (non-base64) entry aborts the whole `list()` call.

**Fix:** defer `fromB64` to first `get()`. `#toEntry` constructs the entry from the raw
encoded password; the entry decodes lazily on access. A single corrupt credential no longer
breaks `list()`.

**Test:** two credentials, one non-base64; assert `list()` returns both entries and the good
entry's `get()` returns its key.

### 6. Prototype cache collisions (Medium) — all caches, all three packages

The stores key plain objects (`{}`) by caller-supplied strings for both the per-instance
`#entries` cache and the static `#byName` / `#byService` open-cache. `entry('constructor')` or
`open('__proto__')` hit prototype members (e.g. `{}.constructor` is `Object`, not nullish, so
`??=` never assigns and a prototype value is cast as an entry/store).

**Fix:** initialize every such cache with `Object.create(null)` in `node`, `browser`, and
`electron` — both the instance `#entries` and the static open-cache. (Audit cited only the
node/browser `entry()` caches; the same bug exists in electron and in all three static
open-caches, so all are fixed to kill the class.)

**Test:** `store.entry('constructor')` returns a real entry (not `Object`); `Store.open` with
a name of `'__proto__'` / `'constructor'` behaves normally.

## Error handling

- New throw: electron encryption-unavailable on write — actionable message naming the Linux
  keyring cause and the `allowInsecureStorage` opt-in.
- Existing IDB and OS-keyring rejections are preserved; the browser commit-fix additionally
  surfaces transaction-level `onabort`/`onerror` as rejections.

## Out of scope

- KeyStore/KeyEntry contract spec and reconciling implementation divergence
  (`next/2026-07-02-keystore-contract-and-adversarial-tests.md`).
- Cross-process atomicity on the node OS keyring (no primitive available; documented only).
