# KeyStore/KeyEntry contract, reconciliation, and adversarial tests — COMPLETE

**Completed:** 2026-07-16
**Status:** complete
**Branch:** `keystore-contract` → PR #9 (https://github.com/TairuFramework/kokuin/pull/9)
**Origin:** `completed/2026-07-02-audit.complete.md` cross-cutting themes 1 & 2.

## Goal

Make `KeyStore`/`KeyEntry` a contract the six keystore backends can actually honor, give
every backend a single `provideIdentity(keyID)` entry point, and close the cross-process
key-loss race behind an opt-in `lockPath`.

## The problem it solved

`token/src/keystore.ts` was a 14-line type with **no consumers** — it existed only as
`implements` clauses, and the backends diverged along the one axis the type could not
express: what each substrate can actually do. HD `setAsync` threw and `removeAsync` was a
silent no-op; `HDKeyEntry.keyID` returned the derivation path, not the caller's keyID; expo
was an object literal whose `entry()` cached nothing and took an undeclared argument; node
and electron both had an unguarded cross-process create race (silent key loss); electron and
expo lacked the prototype-pollution keyID guard node and browser had.

## Key design decisions (preserved from the design spec)

1. **`IdentityProvider<T>` is the load-bearing contract**, not `KeyStore`/`KeyEntry`.
   Consumers are generic over "keyID in, signing identity out". All six backends now
   implement `provideIdentity(keyID)` as a store method; the free
   `provideFullIdentity`/`provideFullIdentityAsync` functions were removed.
2. **Faceted storage contract.** `KeyEntry` (read/provide) is the base; `MutableKeyEntry`
   adds `setAsync`/`removeAsync`. Unsupported operations **cease to exist** rather than
   throwing or no-op'ing. Derived (HD) implements `KeyEntry` only; ledger implements
   **neither** storage facet — the key never leaves the device — and only `IdentityProvider`.
   This is the contract working as designed, not a gap.
   - Implementation note that must not be "simplified" away: the mutable conformance harness
     type is `Omit<KeyStoreConformanceHarness<T>, 'createStore'> & {…}`, **not** a plain
     intersection — an intersection makes TS resolve the base `KeyEntry` facet through the
     overload set and silently drop the mutable facet.
3. **Browser moved off ES256 to non-extractable Ed25519 + X25519**, yielding `FullIdentity`.
   ES256 is no longer minted anywhere in kokuin. Forced design: the agreement key is the
   birational image of the signing key (`ed25519.utils.toMontgomerySecret(seed)`), both
   imported non-extractable via JWK — a `subtle.generateKey`'d X25519 pair would be
   independent and unreachable by any sender. `token` keeps `CODECS.ES256` for *verification*;
   legacy ES256 records keep working **signing-only** and are **never silently re-keyed**
   (that would change the DID). Requires Chrome 137+, Firefox 130+, Safari 17+ — hard-errors,
   no P-256 fallback.
4. **Cross-process lock is opt-in** via `@sozai/lock`'s `withFileLock`, behind a `lockPath`
   option on node and electron. One coarse lockfile per store (not per keyID — a per-keyID
   name would derive from an attacker-influenced keyID). The critical section re-reads
   **inside** the lock so a peer's write is returned, not clobbered. Sync `provide()` throws
   under `lockPath` (a file lock cannot be acquired synchronously). The unguarded race is
   **platform-divergent**: Linux/libsecret upserts unconditionally → silent key loss; macOS
   Keychain throws `errSecDuplicateItem` on the loser.
5. **The `did:peer:4` KEM gap was fixed here**, not deferred (same identity/JWE surface):
   `createTokenEncrypter` threw `Invalid DID format` for every peer:4 recipient (its published
   `keyAgreement` key was unreachable), and `did:key` identities from `createIdentity` could
   not decrypt. peer:4 **long form** reads the published agreement key; **short form** is
   rejected (needs a resolver the sync path cannot await), never silently derived; `did:key`
   derives via the birational map. The base58 decode in `getAgreementKey` was the one path
   that skipped the `MAX_DID_KEY_ENCODED` bound — now bounded.

## What was built

- **token**: the documented faceted contract (`KeyEntry`/`MutableKeyEntry`/`KeyStore`), the
  peer4/did:key KEM fixes.
- **deterministic**: `KeyEntry` only; `entry(x).keyID === x` with the resolved path exposed
  separately as `path`; non-hardened SLIP-0010 segments rejected.
- **node**, **electron**: `PrivateKeyType` is `Uint8Array` in both (electron was base64
  `string`); `MutableKeyEntry` + `IdentityProvider`; opt-in `lockPath`. Electron gained the
  prototype-pollution guard and per-keyID storage keys it lacked.
- **expo**: object literal → class with a cached `entry()` (`entry(x) === entry(x)`) and an
  in-process `provideAsync` lock (single app process, no cross-process race).
- **browser**: non-extractable Ed25519 + X25519 → `did:key` EdDSA `FullIdentity`; legacy
  ES256 records still sign via `provideSigningIdentity`.
- **ledger-device**: documented as `IdentityProvider`-only, pinned with a type test.

## Adversarial testing

A framework-agnostic conformance suite every backend runs, meta-tested against four
deliberately-broken reference stores (wrong-keyID, colliding-slot, uncached-entry, racy) plus
a correct `MemoryKeyStore`, so the suite is proven to have teeth. An e2e test spawns two real
Node processes racing the **real** OS keyring: with `lockPath` both agree; without it, the
test accepts either divergence (Linux) or one racer's `errSecDuplicateItem` (macOS) as proof
the unguarded race manifests.

The conformance suite was later extracted from the published `@kokuin/token` surface into a
private, unpublished `@kokuin/keystore-conformance` package (test-only). Every backend
devDepends on it; `token` keeps only the contract types.

## Post-review refinement (PR #9 iteration)

Following review, every store `open()`/constructor and every `KeyEntry` constructor was
normalised to a **single params object** (`NodeKeyStore.open({ service, lockPath })`,
`ElectronKeyStore.open({ name, allowInsecureStorage, lockPath })`, `BrowserKeyStore.open({ name })`,
`BrowserKeyEntry({ keyID, getStore })`, `ExpoKeyEntry({ keyID, options })`), matching the
shape `deterministic` already used. `HDKeyStore.fromSeed`/`fromMnemonic` keep their
name-paired positional primary. New `*Params` types are exported from each backend
(`ElectronKeyStoreOptions` → `ElectronKeyStoreParams`). The two independent `importKey` calls
in browser `generateKeyRecord` now run via `Promise.all` — the one genuine independent-await
site found in a sweep of `src` (all other sequential awaits are truly dependent: ECDH→KDF→AES
chains, recursive delegation, stateful Ledger APDU chunk-signing, get-then-set).

## Verification

Whole repo green: `build:types` across all packages, full test suite (22 turbo tasks;
node/electron/browser/expo/deterministic/token/capability/otel), biome clean. Crypto verified
by real round-trips (WebCrypto + noble), not by inspection. Breaking changes are permitted
(all packages pre-1.0); `@enkaku` / `@kumiai` are updated as a follow-up, not here.

## Watch-item

The e2e WITHOUT-`lockPath` test's **Linux/gnome-keyring** manifestation (divergence vs
also-throws) is unverified until the first real CI run of `.github/workflows/e2e-node.yml`.
Both e2e tests pass locally on macOS.
