# Refresh auth docs for the store-method identity API

**Origin:** `docs/agents/plans/next/2026-07-16-auth-docs-provide-identity-refresh.md`
**Related:** `docs/agents/plans/completed/2026-07-14-keystore-contract.complete.md` (PR #9)

## Problem

PR #9 replaced the free `provideFullIdentity` / `provideFullIdentityAsync` /
`provideSigningIdentity` functions with methods on each store (the `IdentityProvider`
contract). Only the `.open(...)` signatures in the living docs were corrected at the time;
the rest was deliberately deferred.

Exploration found the drift is wider than the originating item recorded. No package exports
any free `provide*` function today — all six backends expose methods — yet three docs still
publish the old surface, and several surrounding claims describe the pre-PR#9 world:

| Claim in docs | Reality | Source |
|---|---|---|
| `provideFullIdentityAsync(store, keyID)` (node, electron, expo) | `store.provideIdentity(keyID)` | `node/src/store.ts:94` |
| `provideSigningIdentity(keyID[, store])` (browser) | `store.provideSigningIdentity(keyID)` | `browser/src/store.ts:109` |
| Browser is ES256/P-256, `SigningIdentity` only, "decryption is not supported" | Ed25519 + derived X25519; `provideIdentity` returns `FullIdentity`. ES256 is the *legacy* record path — signing-only, never auto-re-keyed (it would change the DID) | `browser/src/store.ts:79`, `packages/browser/README.md` |
| Deterministic: "There is no `provide*` helper" | `HDKeyStore.provideIdentity(keyID)` exists. `auth.md` already contradicts itself — its contract section says to call it | `deterministic/src/store.ts:50` |
| Ledger `provideIdentity` returns a signing identity | Returns `FullIdentity` | `ledger-device/src/provider.ts:82` |
| `ExpoKeyStore.entry(keyID)` | `entry()` is an instance method; the static is `open()`. As written this is a TypeError | `expo/src/store.ts:23,41` |
| `KeyEntry` = `{keyID, getAsync, setAsync, provideAsync, removeAsync}` | `KeyEntry` = `{keyID, getAsync, provideAsync}`; `setAsync`/`removeAsync` moved to `MutableKeyEntry`, which the docs never mention. HD and ledger deliberately do not implement it | `token/src/keystore.ts:21,46` |
| Electron key type `string` (base64, "decoded by the `provide*` helpers") | `MutableKeyEntry<Uint8Array>`; the cited helpers no longer exist | `electron/src/entry.ts:26` |

`docs/reference/capability.md` was checked and is already correct — it is not touched.

## Approach

**Canonical-form-first.** Pin down one correct example shape per package, sourced from the
signatures and cross-checked against the package READMEs (refreshed in PR #9) and
`tests/e2e-node/src/provide.ts:22`, which already uses the target form. Then apply that shape
uniformly across all three docs.

`auth.md` and `auth.skill.md` document the same six packages independently, so fixing call
sites one at a time lets the two drift apart again — that is how the ledger wording already
diverged from `apps/ledger/README.md:101`. Settling the shapes before editing makes the docs
agree by construction.

Rejected: collapsing the duplicated per-package examples into one shared table. It addresses
the duplication at its root but rewrites sections that are currently correct, and is a docs
restructure outside this branch's purpose.

## Canonical shapes

| Package | Form | Source |
|---|---|---|
| node | `await store.provideIdentity(keyID)` → `FullIdentity`; sync twin `store.provideIdentitySync(keyID)` | `node/src/store.ts:94,120` |
| electron | same, sync twin available | `electron/src/store.ts:111,132` |
| expo | same, sync twin available; store via `ExpoKeyStore.open()` | `expo/src/store.ts:23,46,67` |
| deterministic | `await store.provideIdentity(keyID)` → `FullIdentity`; async-only | `deterministic/src/store.ts:50` |
| browser | `await store.provideIdentity(keyID)` → `FullIdentity` (throws on a legacy ES256 record); `await store.provideSigningIdentity(keyID)` accepts both suites, signing-only | `browser/src/store.ts:79,109` |
| ledger | `await provider.provideIdentity(keyID)` → `FullIdentity` | `ledger-device/src/provider.ts:82` |

Every `provide*` name disappears from every `import` — all six are methods.

`node.provideIdentitySync` throws when the store was opened with a `lockPath` (a file lock
cannot be acquired synchronously, `node/src/store.ts:114-118`). Documented wherever the sync
twin is shown.

## Changes

### `docs/reference/auth.md`

- node / electron / expo / deterministic / browser / ledger examples to canonical form; drop
  `provide*` from every `import`.
- Rewrite the browser section: Ed25519 + X25519, `FullIdentity` via `provideIdentity`, ES256
  as the legacy signing-only path. Mirror `packages/browser/README.md`.
- Delete the note block asserting browser has no `provideFullIdentity`.
- Deterministic: remove the false "There is no `provide*` helper" line; show
  `store.provideIdentity('0')`. Resolves the self-contradiction with the contract section.
- Ledger: signing identity → `FullIdentity`.
- Contract section: document the `KeyEntry` / `MutableKeyEntry` split and that HD and ledger
  deliberately omit the mutable facet; electron key type `string` → `Uint8Array`; browser key
  type `CryptoKeyPair` → `StoredKeyRecord`.
- `ExpoKeyStore.entry(keyID)` → `ExpoKeyStore.open().entry(keyID)`.
- Note the sync-twin `lockPath` caveat.

### `docs/skills/auth.skill.md`

- Patterns 2–7 to canonical form; drop `provide*` from every `import`.
- Pattern 3 (browser): rewrite prose and key points to the Ed25519 + X25519 reality.
- Pattern 4 (expo): fix `ExpoKeyStore.entry(...)`.
- Pattern 6 (deterministic): remove the "No `provide*` helper" key point.
- Pattern 7 (ledger): signing identity → `FullIdentity`.
- "When to Use What": correct the browser entry ("signing identity only — no decryption").

### `docs/skills/discover.skill.md`

- Lines 28–31: drop the removed export names; state the store-method surface.

## Verification

Extract every TypeScript snippet from the three docs into a scratch file under the scratchpad
directory, typecheck against the built `lib/` types, discard. Catches wrong call shapes and
the `ExpoKeyStore.entry` class of error.

Snippets needing runtime values (`masterSeed`, Ledger `transport`) get `declare const` stubs
— typecheck only, nothing executes.

No checked-in harness. Permanent doc-snippet gating belongs to
`docs/agents/plans/next/2026-07-02-ci-release-gating.md`, which already owns pipeline work;
forking it here would duplicate that effort.

## Out of scope

- Restructuring the duplicated per-package examples across `auth.md` / `auth.skill.md`.
- A permanent docs-snippet check in CI (owned by the `ci-release-gating` item).
- `docs/reference/capability.md` — verified correct.

## Success criteria

- No free `provide*` function name appears in any of the three docs.
- Every example matches the canonical shape for its package.
- All snippets typecheck against the built `lib/` types.
- Browser, deterministic, ledger, expo, `KeyEntry`/`MutableKeyEntry`, and the electron key
  type claims match the source cited in the Problem table.
- Docs and package READMEs agree.
