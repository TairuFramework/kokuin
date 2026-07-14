# KeyStore/KeyEntry contract, implementation reconciliation, and adversarial tests

**Date:** 2026-07-13
**Origin:** `docs/agents/plans/next/2026-07-02-keystore-contract-and-adversarial-tests.md`
(itself from `completed/2026-07-02-audit.complete.md`, cross-cutting themes 1 & 2)
**Prerequisite:** met — `@sozai/lock@0.1.0` is published. Its public API is
`withFileLock(lockPath, fn, options?)` / `acquireFileLock(lockPath, options?)`, throwing
`TimeoutInterruption` when acquisition times out (default 10s), which is what the
"Cross-process lock" section below assumes. Same-process callers on one path queue FIFO
(`enterQueue`), so the coarse one-lockfile-per-store design does not deadlock across
concurrent keyIDs; only *nested* acquisition would, and `provideAsync` never nests.

## Problem

`packages/token/src/keystore.ts` is 14 lines with zero JSDoc, and it has **no consumers**.
Nothing in `token` uses `KeyStore` or `KeyEntry`; no function anywhere takes one as a
parameter. They exist only as `implements` clauses on five store/entry classes — a
conformance checklist, not an abstraction. And they fail even at that, because the
implementations diverge along the one axis the type cannot express: what the underlying
substrate can actually do.

The audit named five divergences. Investigation found more, and found that the real
abstraction is elsewhere.

### The five shapes of one operation

Every package answers "give me an identity for this keyID" differently:

| Package | `PrivateKeyType` | Identity surface | Yields |
|---|---|---|---|
| browser | `CryptoKeyPair` | `provideSigningIdentity(keyID, store?)` | ES256 `SigningIdentity` |
| node | `Uint8Array` | `provideFullIdentity(store, keyID)` + sync twin | Ed25519 `FullIdentity` |
| electron | `string` (base64) | `provideFullIdentity(store, keyID)` + sync twin | Ed25519 `FullIdentity` |
| expo | `Uint8Array` | `provideFullIdentity(keyID)` — no store arg | Ed25519 `FullIdentity` |
| deterministic | `Uint8Array` | `HDKeyStore#provideIdentity(keyID)` | Ed25519 `FullIdentity` |
| ledger-device | *none* | `createLedgerIdentityProvider(transport)` | Ed25519 `FullIdentity` |

`IdentityProvider<T>` already exists (`packages/token/src/identity.ts:49-51`) and is the
thing consumers are actually generic over — keyID in, signing identity out. Ledger, which
cannot expose key material at all, implements it cleanly. Only 2 of 6 packages do.

**`IdentityProvider` is the load-bearing contract. `KeyStore`/`KeyEntry` is the storage
contract, and it needs to stop lying.**

### Divergences and bugs found

Beyond the audit's list:

- **`HDKeyEntry.keyID` returns the derivation path, not the caller's keyID**
  (`deterministic/src/entry.ts:20`, resolved at `store.ts:42-44`). `store.entry(x).keyID !== x`.
  Every other store round-trips it.
- **HD `getAsync()` can never return `null`** (`entry.ts:29-31`) — it derives. The
  `existing != null` branch every other package uses is dead code there.
- **HD `setAsync` throws** (`entry.ts:33-35`) and **`removeAsync` is a silent no-op**
  (`entry.ts:41-43`) — the body is a lone comment. It resolves; the key is still derivable.
- **`ExpoKeyStore` is an object literal**, not a class (`expo/src/store.ts:5`). Its `entry()`
  caches nothing — `entry(x) !== entry(x)` — and takes an **undeclared second argument** the
  `KeyStore` type does not have.
- **Expo `provideAsync` has no lock** (`entry.ts:50-58`); node has an in-process one, browser
  uses an IndexedDB transaction.
- **Node's cross-process race.** `@napi-rs/keyring`'s write is an unconditional upsert — no
  CAS. `provideAsync` is read-if-absent/generate/write, not atomic across processes.
  `node/src/entry.ts:13-15` concedes `#provideLock` is in-process only. Two processes on a
  fresh keyID both generate, both write; the loser signs with a key no longer in the
  keychain. Silent key loss. **`@kokuin/electron` has the identical bug** — `electron-store`
  is a plain JSON file, and two app instances race the same way.
- Prototype-pollution keyID guards exist in browser and node, **not** in electron or expo.

### Why browser is different

Browser stores a **non-extractable** `CryptoKeyPair` — the private key cannot be read out,
even by XSS. That is a real security win, and it is *why* browser diverges: WebCrypto will
not let an `ECDSA` key do `deriveBits`, so it cannot do ECDH, so it cannot offer
`decrypt`/`agreeKey`, so it yields `SigningIdentity` and not `FullIdentity`. The same keyID
therefore produces a **different DID** in a browser than in node.

This cannot be closed with P-256. Making browser do ECDH requires a *separate* ECDH keypair,
whose public key a `did:key` ES256 DID has no room to carry — so a peer could never resolve
it. (`jwe.ts` is X25519-only by design: `resolveX25519Key` at `jwe.ts:135-145` accepts an
`EdDSA` DID and derives X25519 from it by the birational map, and throws on anything else.)
Publishing the agreement key would mean requiring `did:peer:4` documents for all browser
identities.

The answer is to drop ES256 rather than extend the JWE layer.

## Decisions

1. **Breaking changes are permitted.** All packages are pre-1.0. `@enkaku` and `@kumiai` get
   updated as a follow-up.
2. **Faceted storage contract.** The type reflects the substrate; unsupported operations
   *cease to exist* rather than throwing or no-op'ing.
3. **`IdentityProvider` on all six packages.** One signature, `provideIdentity(keyID)`.
4. **Browser moves to Ed25519 + X25519**, non-extractable, yielding `FullIdentity`. ES256 is
   no longer minted anywhere in kokuin. The keys are **imported**, not generated by WebCrypto
   — see "Browser key generation" below for why that is forced.
5. **`token` keeps `CODECS.ES256` for verification.** Tokens already signed by browser
   identities in the field stay verifiable; third-party ES256 DIDs stay acceptable.
6. **Legacy ES256 records keep working, signing-only.** No silent re-keying, ever.
7. **Cross-process lock is opt-in**, via `@sozai/lock`, behind a `lockPath` option.
8. **`readonly` stays on type members.** The kigu rule is class-scoped.
9. **The `did:peer:4` KEM gap is fixed here**, not deferred — see below. Found while planning
   this work, confirmed by test, and it touches the same identity/JWE surface.

## The contract

`packages/token/src/keystore.ts`, fully documented:

```ts
type KeyEntry<PrivateKeyType> = {
  readonly keyID: string
  getAsync(): Promise<PrivateKeyType | null>
  provideAsync(): Promise<PrivateKeyType>
}

type MutableKeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType> & {
  setAsync(privateKey: PrivateKeyType): Promise<void>
  removeAsync(): Promise<void>
}
```

`KeyStore<PrivateKeyType, EntryType>` is unchanged — it is already parameterized by entry
type, so a mutable store is `KeyStore<T, MutableKeyEntry<T>>`. No new store type is needed.

`IdentityProvider<T extends SigningIdentity>` becomes the consumer-facing contract, and the
five free functions above collapse into `store.provideIdentity(keyID)`.

### Invariants

Written into JSDoc, and enforced by a shared conformance suite (below):

1. **keyID round-trips.** `store.entry(x).keyID === x`.
2. **Absent means `null`.** `getAsync()` returns `null` when no key exists — never
   `undefined`, never throws. (A derived store may never return `null` at all; that is
   contract-legal.)
3. **`provideAsync` is idempotent under concurrency.** Two concurrent calls resolve to the
   *same* key. Never two keys, never a lost key.
4. **Identity-only backends are first-class.** A backend whose key never leaves the device
   implements `IdentityProvider` and neither storage type. This is the contract working, not
   an omission.

## Per-package reconciliation

### deterministic

- Implements `KeyEntry` only. `setAsync` and `removeAsync` are **deleted** — the type now
  says what the substrate can do, so there is nothing to throw from and nothing to no-op.
- **Fix `keyID`** to return the caller's keyID. Expose the resolved derivation path
  separately as `path`.
- Document that derived stores never return `null` from `getAsync`.
- Non-hardened derivation paths must throw (SLIP-0010 ed25519 requires hardened).

### ledger-device

- Implements neither `KeyStore` nor `KeyEntry` — only `IdentityProvider`. Already true;
  now it is documented as intended, not as a gap.

### browser

Substrate: two non-extractable WebCrypto keys — Ed25519 for signing, X25519 for agreement.
Yields `FullIdentity`. DID algorithm now matches node/HD/ledger. The browser identity keeps
a `did:key` EdDSA DID, so **the JWE layer needs no change to serve it**.

#### Browser key generation

`subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])` **cannot be used.** It mints
an *independent* keypair, and a sender never sees that key: `jwe.ts`'s `resolveX25519Key`
(:135-145) **derives** the recipient's agreement key from the DID's Ed25519 signing key via
`ed25519.utils.toMontgomery`. An independently generated X25519 key is therefore unreachable
by any sender, however it is stored. This is the same structural failure that killed P-256 —
it applies to a generated X25519 key too.

The agreement key must be the birational image of the signing key, which needs the Ed25519
private scalar — and a non-extractable `generateKey` result never yields it.

So browser **generates the seed itself and imports both keys as non-extractable**:

```ts
const seed = ed25519.utils.randomSecretKey()
const edPub = ed25519.getPublicKey(seed)
const xPriv = ed25519.utils.toMontgomerySecret(seed)
const xPub = x25519.getPublicKey(xPriv) // === ed25519.utils.toMontgomery(edPub)

signing = await subtle.importKey(
  'jwk', { kty: 'OKP', crv: 'Ed25519', d: b64u(seed), x: b64u(edPub) },
  { name: 'Ed25519' }, false, ['sign'],
)
agreement = await subtle.importKey(
  'jwk', { kty: 'OKP', crv: 'X25519', d: b64u(xPriv), x: b64u(xPub) },
  { name: 'X25519' }, false, ['deriveBits'],
)
```

Verified on Node 26: the imported agreement key's ECDH output equals what a sender computes
from the DID alone, WebCrypto's Ed25519 signature verifies under noble, and `exportKey`
refuses both keys with `InvalidAccessError`.

**The cost, stated plainly:** the raw seed exists in the JS heap during generation, where
`generateKey` would never have exposed it. It is zeroed after import, and IndexedDB only ever
holds non-extractable `CryptoKey`s — so XSS at any point *after* provisioning still cannot
exfiltrate. The exposure is one tick, once per keyID. That is a real but bounded weakening,
and it is the price of being addressable by a `did:key` DID at all.

The stored record is **tagged with its suite**. An untagged record is ES256 by definition
(that is all a legacy record can be), so legacy keys still load and sign while new keys are
Ed25519. Because a legacy record can only sign, browser cannot statically promise
`FullIdentity` from one method:

```ts
provideIdentity(keyID): Promise<FullIdentity>            // IdentityProvider conformance; throws on a legacy ES256 record
provideSigningIdentity(keyID): Promise<SigningIdentity>  // accepts both; returns FullIdentity as a subtype when Ed25519
```

New code gets full static guarantees; legacy consumers get an explicit door. No conditional
types.

**Ed25519/X25519 availability is feature-detected and hard-errors when absent. It must never
fall back to P-256** — a silent fallback mints a different DID for the same keyID, which is
identity loss.

The low-S normalization (`browser/src/identity.ts:28-33`) survives, scoped to the legacy
ES256 signing path. It exists because WebCrypto's ECDSA emits high-S and the token verifier
runs `lowS: true`.

### node

- `MutableKeyEntry`; `IdentityProvider<FullIdentity>` via a `provideIdentity` method.
- Sync twins (`get`/`set`/`provide`/`remove`) stay as extra methods. The contract is a floor,
  not a ceiling.
- Gains `lockPath` (below).

### electron

- `PrivateKeyType` changes from `string` to `Uint8Array`, matching every other store. Base64
  encode/decode moves inside the entry, deleting the `decodePrivateKey` calls threaded
  through `electron/src/identity.ts`.
- `MutableKeyEntry`; `IdentityProvider<FullIdentity>`.
- Gains `lockPath` (below).
- Gains the prototype-pollution keyID guard it lacks.

### expo

- `ExpoKeyStore` becomes a class with `open(options?)`. The undeclared second argument to
  `entry()` moves to construction, so the store conforms to `KeyStore` as written.
- Add the entry cache it lacks, so `entry(x) === entry(x)`.
- Add the in-process `provideAsync` lock it lacks.
- Gains the prototype-pollution keyID guard it lacks.
- No cross-process lock: a single app process makes it moot.

## The `did:peer:4` KEM gap

Found while planning the browser change, and confirmed by `token/test/peer4-kem.test.ts`
(5 passing assertions against the current code):

- `createIdentity` with a `kem` X25519 key publishes it in the peer:4 doc's `keyAgreement`,
  and `MultiKeyIdentity.agreeKey` uses its private half.
- But `createTokenEncrypter` throws **`Invalid DID format`** for a peer:4 DID, short form *or*
  long form — `resolveX25519Key` calls the sync `getSignatureInfo`, which parses `did:key`
  only. **No sender can encrypt to a peer:4 identity at all.** The published agreement key is
  dead weight.
- The key jwe *would* derive if it could parse peer:4 — `toMontgomery(signingPublicKey)` — is
  provably not the published `keyAgreement` key, and decryption with it fails.
- Separately, `createIdentity`'s **`did:key`** path throws `No KEM key in identity` from
  `agreeKey`, so it cannot decrypt either — unlike `createFullIdentity`, which montgomery-derives.

Fix, in `token`:

1. **`resolveX25519Key` learns peer:4.** A peer:4 **long form** resolves its doc inline and
   uses the published `keyAgreement` X25519 key (codec `0xec 0x01`). A `did:key` EdDSA
   recipient keeps montgomery-deriving — unchanged, and this is the path browser/node/HD/ledger
   all use. A peer:4 **short form** cannot be resolved synchronously, so it throws a specific
   error naming the missing doc rather than the generic `Invalid DID format`.
2. **A peer:4 doc with no `keyAgreement` throws** a distinct "recipient publishes no agreement
   key" error. Silent unreachability is the failure mode this whole section exists to remove.
3. **`createIdentity`'s `did:key` path gains `agreeKey`/`decrypt`** by montgomery-deriving from
   its single Ed25519 signing key, matching `createFullIdentity`. A `did:key` identity is
   encryptable-to by definition; refusing to decrypt was simply wrong.

## Cross-process lock

Opt-in, backed by `@sozai/lock`:

```ts
NodeKeyStore.open(service, { lockPath })
ElectronKeyStore.open(name, { allowInsecureStorage, lockPath })
```

Absent `lockPath`, nothing touches the filesystem and the existing in-process `#provideLock`
still applies. The option **adds** cross-process exclusion; it does not replace what is
there.

`lockPath` is a **file**, not a directory — one coarse lock per store, not one per keyID.
A per-keyID lockfile would derive its filename from an attacker-influenced `keyID`
(path traversal: `entry("../../../etc/x")`), and `provideAsync` runs once per identity, so
serializing across keyIDs costs nothing real. Coarse locking is a strict superset of the
exclusion needed, with none of the filename-sanitization risk.

Sequence inside `provideAsync` when `lockPath` is set:

1. Acquire the lock (blocking, with backoff).
2. **Re-read the credential.** A peer may have created it while we waited. If present,
   release and return it. This step is what makes the lock pay off — without it the winner
   clobbers the peer's key.
3. Otherwise generate, write, read back to confirm, release, return.

**Failing to acquire within the timeout throws.** It never proceeds unlocked — that would
drop the guard exactly when contention is real.

Re-`open()`ing a service with a *different* `lockPath` throws rather than silently keeping
the first, matching the precedent `ElectronKeyStore.open` already sets for a conflicting
`allowInsecureStorage`.

## Tests

### Shared conformance suite

Lives in `token`, parameterized over a `KeyStore` factory, run by every implementation.
Pins the invariants above: keyID round-trip, absent ⇒ `null`, concurrent `provideAsync`
convergence. This is what makes a sixth backend cheap, and it is what would have caught the
electron two-keys bug.

### Per-package adversarial cases

- **Two keys in one store** — electron (the audit's Critical #4; currently untested there).
- **Non-hardened HD derivation paths** must throw.
- **Corrupt / non-base64 credentials** — every store that decodes.
- **Prototype-pollution keyIDs** (`entry("constructor")`, `entry("__proto__")`) — electron and
  expo lack the guard browser and node have.
- **Path-traversal keyIDs** — including with `lockPath` set.
- **Legacy ES256 records** — browser: still sign, `provideIdentity` throws, `provideSigningIdentity`
  works, and no silent re-key.
- **Suite mismatch on a stored browser key** — a stored suite always wins over the requested
  one.
- **Ed25519 unavailable** — browser hard-errors, never falls back.
- **Browser agreement key is reachable from the DID alone** — the regression test for the trap
  that `generateKey` walks into: derive `toMontgomery(edPub)` from the identity's DID, encrypt
  to it, and assert the browser identity decrypts it.
- **peer:4 KEM** (`token/test/peer4-kem.test.ts`, already written) — currently pins the gap;
  flipped to assert the fix.

Out of scope: `alg:none`, tampered delegation chains, prefix permissions. Those belong to
token and capability — spun out.

### Node e2e

`tests/e2e-node` — a small spawned CLI, not a GUI app like the other three e2e suites.

Its centerpiece is the **cross-process race**: two real Node processes race `provideAsync`
against a **real** Secret Service. Without `lockPath` it demonstrates the key loss; with
`lockPath` it proves the loss is closed. An in-process mock structurally cannot test this —
which is exactly why the bug survived the existing suite.

New `.github/workflows/e2e-node.yml`, written **locally in kokuin** (Ubuntu runner with
`dbus` + `gnome-keyring`), not a `kigu` reusable workflow. It must **not** `skipIf` the
daemon away when absent — that is the silent-green pattern the ci-release-gating item
already flags on the Speculos suite.

## Conventions

`readonly` stays on the three type members repo-wide (`token/src/keystore.ts:2`,
`token/src/identity.ts:16`, `ledger-device/src/errors.ts:2`). The kigu rule sits under
*Class Conventions* and its stated rationale is runtime enforcement via `#field` + getter,
which is meaningless for a type literal that has no runtime. Every class already satisfies
these with a getter. Propose a wording clarification upstream in the kigu conventions skill.

## Follow-ups

- Rebase `@tejika/process` onto `@sozai/lock` so one implementation exists in the stack.
- Update `@enkaku` and `@kumiai` for the kokuin API changes.
- Adversarial tests for token and capability (`alg:none`, delegation chains, prefix
  permissions).
- Kigu conventions wording clarification for `readonly`.

## Out of scope

- **ECDH-ES P-256 in `jwe.ts`.** Dropped: a `did:key` ES256 DID cannot carry an agreement
  key, which is why browser moves to Ed25519 instead of extending the JWE layer. (`jwe.ts`
  *is* touched by this work, but only to teach `resolveX25519Key` about `did:peer:4` — no
  new curve.)
- **Async DID resolution in `createTokenEncrypter`.** A peer:4 **short form** needs a
  `DIDResolver`, which the sync constructor cannot await. It throws with a specific error;
  long form works. Making the encrypter async is a separate API decision.
- `docs/agents/plans/next/2026-07-02-ci-release-gating.md`.
- `docs/agents/plans/next/2026-07-10-verified-token-mutation-and-decode-hardening.md`.
