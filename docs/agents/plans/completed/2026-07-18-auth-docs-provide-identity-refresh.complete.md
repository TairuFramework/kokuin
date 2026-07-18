# Auth docs refresh for the store-method identity API — COMPLETE

**Completed:** 2026-07-18
**Status:** complete
**Branch:** `docs/provide-identity-refresh`
**Origin:** deferred documentation work from `completed/2026-07-14-keystore-contract.complete.md` (PR #9).

## Goal

Bring the three living auth docs in line with the identity API PR #9 shipped, and correct the
surrounding claims that still described the pre-PR#9 world.

## The problem it solved

PR #9 replaced the free `provideFullIdentity` / `provideFullIdentityAsync` /
`provideSigningIdentity` functions with a `provideIdentity(keyID)` **method** on each store
(the `IdentityProvider` contract). Only the `.open(...)` signatures were corrected at the time.

Exploration found the drift was wider than the deferred item recorded. No package exported any
free `provide*` function, yet three docs still published that surface, and seven distinct claims
were factually wrong:

- **Browser** was described as ES256/P-256, `SigningIdentity` only, "decryption is not
  supported". Reality is nearly the inverse: a non-extractable Ed25519 signing key plus a
  derived X25519 agreement key, so it both signs and decrypts. ES256 is the *legacy* record
  path — signing-only, because WebCrypto will not let an ECDSA key do `deriveBits` — and is
  never silently re-keyed, since that would change the DID.
- **Deterministic** claimed "there is no `provide*` helper". `HDKeyStore.provideIdentity` exists
  (async-only, no sync twin). The reference doc already contradicted itself: its contract
  section told readers to call it.
- **Ledger** was documented as returning a signing identity; it returns a `FullIdentity`.
- **`ExpoKeyStore.entry(keyID)`** was shown as a static. `entry()` is an instance method and the
  static is `open()` — as written the example was a TypeError.
- **`KeyEntry`** was documented as `{keyID, getAsync, setAsync, provideAsync, removeAsync}`.
  The write half moved to `MutableKeyEntry`, which the docs never mentioned, and which HD and
  ledger deliberately do not implement.
- **Electron's key type** was `string` (base64, "decoded by the `provide*` helpers"). It is
  `MutableKeyEntry<Uint8Array>`; base64 was the storage encoding, never the entry's key type.
- The **keystore section intro** claimed all keystores implement `KeyStore`/`KeyEntry`. Ledger
  implements `IdentityProvider` alone — the key never leaves the device, so it has neither
  storage type and no keystore class. That is the contract working, not a gap.

## Key design decisions

**Canonical-form-first, not fix-per-site.** `docs/reference/auth.md` and
`docs/skills/auth.skill.md` document the same six packages independently. That duplication is
what let them drift, and it is how the ledger wording diverged from `apps/ledger/README.md`.
Fixing call sites one at a time would have let them drift apart again. Instead one correct shape
per package was pinned from the signatures first — cross-checked against the package READMEs
(refreshed in PR #9) and `tests/e2e-node/src/provide.ts`, which already used the target form —
then applied uniformly. The docs agree by construction rather than by inspection.

**Rejected:** collapsing the duplicated per-package examples into one shared table. It addresses
the duplication at its root, but rewrites sections that are currently correct and is a docs
restructure, not a correction.

**Throwaway verification harness, deliberately not checked in.** A temporary extractor pulled
every fenced TypeScript block from the docs and typechecked it against the built `lib/` types.
It extracted from the live docs rather than copying them, so the gate could not drift from what
it gated — a copied fixture would have reproduced the same drift problem one layer down. It
lived untracked in the repo root (it must resolve `@kokuin/*` by relative path to each package's
built `lib/index.d.ts`; there is no root `node_modules/@kokuin` symlink, because pnpm links
workspace packages only into each consumer's own `node_modules`) and was deleted once green.

Permanent doc-snippet gating was explicitly kept out of scope — it belongs to the CI release
gating item in `next/`, which already owns pipeline work.

The trade this makes: the "all snippets typecheck" criterion is not reproducible after teardown.
The final reviewer compensated by hand-reading all 27 blocks against source rather than trusting
the recorded green run, and endorsed the trade.

## What was built

Nine commits, docs only — no source, config, or test file touched.

- **`docs/reference/auth.md`** — all six keystore examples to canonical form; browser section
  rewritten to the Ed25519 + X25519 reality; contract section documents the
  `KeyEntry`/`MutableKeyEntry` split and the HD/ledger omission of the mutable facet; electron
  key type corrected to `Uint8Array`, browser to `StoredKeyRecord`; section intro corrected.
- **`docs/skills/auth.skill.md`** — patterns 2–7 to canonical form, Pattern 3 (browser)
  rewritten, "When to Use What" browser entry corrected.
- **`docs/skills/discover.skill.md`** — package blurbs list the store-method surface; the token
  blurb now names all four contract types it exports (`KeyStore`, `KeyEntry`, `MutableKeyEntry`,
  `IdentityProvider`).

`docs/reference/capability.md` was checked and found already correct; it was not touched.

## Verification

The harness reported exactly 10 errors against the pre-change docs — every one a defect named
above, including independent compiler confirmation of the `ExpoKeyStore.entry` TypeError. It
finished at 0 errors across 23 typechecked blocks, then was removed.

Sections the harness could not gate were covered by review against source: `discover.skill.md`
has no TypeScript blocks at all, and blocks declaring types (the `Identity` hierarchy,
`SignedPayload`, the `KeyEntry` contract, `IdentityProvider`) were skipped by the extractor
because they redeclare imported names.

Every task was reviewed, plus a whole-branch review at the end. That final pass caught one
defect the per-task reviews structurally could not: each task owned a keystore subsection, so
none owned the section header above them, which still carried the removed free-function framing.

## Known gaps

`@kokuin/expo` and `@kokuin/electron` both expose a `provideIdentitySync` twin that the docs do
not show; only Node's is documented. Nothing false is stated. Tracked in
`backlog/2026-07-18-document-expo-electron-sync-twins.md`.
