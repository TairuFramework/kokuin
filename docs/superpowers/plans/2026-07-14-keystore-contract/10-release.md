# Release — changesets, docs, full-repo verification

Task 14. The repo has been red at `build:types` since Task 1 (every commit up to Task 11 used `--no-verify`). This is where it goes green and stays green.

**Files:**
- Create: `.changeset/*.md` (one per changed package, or one covering several)
- Modify: `packages/*/README.md` for the packages whose public API changed
- Modify: `AGENTS.md` if the backend table there is now wrong

**Interfaces:**
- Consumes: everything.
- Produces: a releasable branch.

- [ ] **Step 1: Verify the whole repo**

From the repo root, in this order:

```bash
pnpm install
pnpm exec biome check --write ./packages
rtk proxy pnpm run -r build:types
rtk proxy pnpm run test
```

Expected: biome clean, all 13 packages type-check, every package's `test:types` and `test:unit` pass.

Fix anything that fails **before** writing changesets. If a package outside this plan's scope broke (`capability`, `otel`), that is a real regression from the `token` changes — investigate it, do not paper over it.

- [ ] **Step 2: Write the changesets**

Every published package that changed needs one. All are pre-1.0, so a breaking change is a `minor` bump (a `major` on a 0.x is not what changesets does by default, and the repo is pre-1.0 by policy — see spec decision 1).

Create `.changeset/keystore-contract.md`:

```markdown
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
  `string`). Both gain an opt-in `lockPath` that closes the cross-process race where two
  processes both generate a key for a fresh keyID and the loser's key is silently lost.
  Electron also gains the prototype-pollution guard it lacked.
- **expo**: `ExpoKeyStore` becomes a class with a cached `entry()` and a `provideAsync` lock.
  Its `entry()` no longer takes an undeclared second argument — options move to construction.
- **deterministic**: `entry(x).keyID` now returns `x` rather than the derivation path (exposed
  separately as `path`). Non-hardened derivation paths throw.
```

- [ ] **Step 3: Update the package READMEs**

Read each `packages/*/README.md` first — several are one-liners and need no change. Update any that show the old API:

- Any README calling `provideFullIdentity(store, keyID)` → `store.provideIdentity(keyID)`.
- `packages/browser/README.md` — state the Ed25519 requirement and the browser version floor, and that legacy ES256 keys sign but do not decrypt.
- `packages/node/README.md`, `packages/electron/README.md` — document `lockPath`, that it is opt-in, that it must be a local-filesystem path, and that the sync `provide()` throws under it.

- [ ] **Step 4: Check `AGENTS.md`**

`AGENTS.md` describes the packages and the release groups. Two things to check:

- Does it describe the keystores in a way this work invalidates? Update it if so.
- The fixed release group is "token, capability, browser, node, deterministic" — `expo`, `electron`, and `ledger-device` float. This plan changes packages in both sets, which is fine, but confirm the changeset above matches how the groups actually release.

- [ ] **Step 5: Final verification and commit**

```bash
rtk proxy pnpm run -r build:types
rtk proxy pnpm run test
pnpm exec biome check ./packages
```

All three clean. Then commit **without** `--no-verify` — the hook must pass on its own now:

```bash
git add .changeset packages/*/README.md AGENTS.md
git commit -m "$(cat <<'EOF'
chore: changesets and docs for the keystore contract work
EOF
)"
```

- [ ] **Step 6: Open the PR**

```bash
git push -u origin keystore-contract
gh pr create --title 'feat: keystore contract, reconciliation, and adversarial tests' --body "$(cat <<'EOF'
Implements `docs/superpowers/specs/2026-07-13-keystore-contract-design.md`.

`KeyStore`/`KeyEntry` had no consumers and the six backends "conformed" to it by throwing
(`HDKeyEntry.setAsync`), silently no-op'ing (`HDKeyEntry.removeAsync`), or not participating
at all (ledger). This makes the type reflect what each substrate can actually do, and makes
`IdentityProvider` the contract consumers are generic over.

## Highlights

- **A faceted contract.** `KeyEntry` (read/provide) and `MutableKeyEntry` (write/delete), plus
  a framework-agnostic conformance suite in `token` that every backend runs. It is what makes
  a seventh backend cheap, and it catches the electron "two keys in one store" bug.
- **Cross-process key loss, closed.** `@napi-rs/keyring`'s write is an unconditional upsert
  with no compare-and-set, so two node processes on a fresh keyID both generate, both write,
  and the loser signs with a key no longer in the keychain. Same bug in electron via
  `electron-store`. Both gain an opt-in `lockPath` backed by `@sozai/lock`. `tests/e2e-node`
  races two **real** processes against a **real** Secret Service to prove it — a mock cannot.
- **Browser yields a `FullIdentity`.** Non-extractable Ed25519 + the X25519 key derived from
  it, so a browser identity has the same `did:key` EdDSA shape as every other backend. The
  keys are *imported*, not `generateKey`'d — see the spec for why the obvious mechanism is
  silently broken.
- **`did:peer:4` identities were unencryptable-to.** Found while planning: `resolveX25519Key`
  called the `did:key`-only `getSignatureInfo`, so `createTokenEncrypter` threw for every
  peer:4 recipient and the `keyAgreement` key published in the doc was dead weight. Fixed.

## Follow-ups (not in this PR)

- Update `@enkaku` and `@kumiai` for the API changes.
- Rebase `@tejika/process` onto `@sozai/lock`.
- Adversarial tests for `token` and `capability` (`alg:none`, delegation chains, prefix
  permissions).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
