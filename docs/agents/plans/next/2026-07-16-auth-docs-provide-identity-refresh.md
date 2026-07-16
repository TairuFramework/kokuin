# Refresh auth docs for the store-method identity API

**Priority:** next (user-facing docs show a removed API)
**Related:** `completed/2026-07-14-keystore-contract.complete.md`

## Problem

The keystore-contract work (PR #9) removed the free `provideFullIdentity` /
`provideFullIdentityAsync` functions and made `provideIdentity(keyID)` a **method** on each
store (the `IdentityProvider` contract). Browser's `provideSigningIdentity` also became a
store method. Two living docs still show the old free-function form and will not run:

- `docs/reference/auth.md`
  - imports and calls `provideFullIdentityAsync(store, 'main-key')` (node example)
  - calls `provideSigningIdentity('user-session', store)` (browser example)
- `docs/skills/auth.skill.md`
  - comment + calls around `provideFullIdentity` (node example)
  - calls `provideSigningIdentity('session-key')` and `provideSigningIdentity('session-key', store)`

Only the `.open(...)` signatures in these files were corrected during PR #9; the
removed-function calls were left as a deliberately-scoped follow-up.

## Fix

Rewrite the examples to the current surface:

- node/electron/expo/deterministic: `const identity = await store.provideIdentity(keyID)`
  (sync twin `store.provideIdentitySync(keyID)` where the backend offers it — node, electron,
  expo; deterministic and ledger are async-only).
- browser: `await store.provideIdentity(keyID)` for a `FullIdentity` (throws on a legacy
  ES256 record — it cannot decrypt), or `await store.provideSigningIdentity(keyID)` to accept
  both suites signing-only.
- Drop the removed names from every `import`.

Cross-check against the current package READMEs (node/electron/browser were refreshed in
PR #9) so the docs and READMEs agree. Verify any TypeScript snippet compiles against the
built `lib/` types.
