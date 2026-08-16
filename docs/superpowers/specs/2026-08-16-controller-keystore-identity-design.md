# did:kokuin FullIdentity from a keystore -- design

**Status:** approved, ready for planning
**Date:** 2026-08-16
**Repo:** kokuin

## Goal

Give consumers a high-level way to obtain a ready `did:kokuin:` **FullIdentity** (signing plus
decryption) from an existing keystore, without teaching any keystore about controllers. A keystore
stores the seed; a single utility folds the log and hands back a `FullIdentity`, generating a fresh
identity on first use and restoring an existing one afterwards.

## Background

Today the two layers are disjoint:

- The keystore packages (`browser`, `node`, `electron`, `expo`, `deterministic`) each mint a
  `did:key` identity: one Ed25519 key per `keyID`, `provideIdentity` returns a `FullIdentity` whose
  DID is `did:key:z...`. None references `did:kokuin`, a profile, a seed tree, or the controller.
- `@kokuin/controller` builds a `did:kokuin:` identity from a raw `seed: Uint8Array` plus a numeric
  `profile` index and an event log. It derives every key from that seed via its own
  `authorityPath` / `agreementPath` / `recoveryPath` tree, and produces a **`SigningIdentity`
  only** -- it has no key-agreement or decryption path at all, even though every inception carries
  X25519 agreement keys (`ka`).

So a consumer cannot ask a keystore for a `did:kokuin` identity, and even the controller's own
entry points cannot decrypt. This design closes both gaps.

## Decisions taken

These were settled during brainstorming and are fixed for the plan:

1. **Full FullIdentity now.** The controller gains its first key-agreement / decryption path so the
   utility returns a true `FullIdentity`, not a signing-only stand-in.
2. **LogStore-backed, generate and restore.** The utility loads the log from a `LogStore`,
   bootstrapping a fresh inception when none exists. One call serves both a new and an existing
   identity.
3. **A `KeyEntry`'s raw private-key bytes are the controller seed.** `provideAsync()` already gives
   generate-if-absent / restore-if-present for raw-byte keystores, so no new storage type is
   needed. `keyID` names the seed; `profile` selects identities under it.
4. **The utility lives in `@kokuin/controller`.** The controller already depends on `@kokuin/token`
   (which owns `KeyStore` / `KeyEntry`) and defines `LogStore`, so no new package and no cyclic
   dependency. Keystores are untouched. v1 covers `node`, `electron`, `expo`, `deterministic`;
   `browser` and `ledger` are deferred (see Scope).

## Architecture

Four units, bottom-up.

### 1. Token: a DID-bound key-agreement primitive

`@kokuin/token` has `createSigningIdentityForDID(did, privateKey)` -- a signing identity whose `id`
is a caller-supplied DID rather than the key's own `did:key`. It has no agreement counterpart:
`createKeyAgreementIdentity(privateKey)` derives the `id` from the X25519 key, which is the wrong
DID for a controller.

Add the missing mirror:

- `createKeyAgreementIdentityForDID(did, x25519PrivateKey): KeyAgreementIdentity` -- runs ECDH
  directly on a raw X25519 scalar (not an Ed25519 key to Montgomery-convert, as
  `createKeyAgreementIdentity` does -- a controller derives an independent agreement keypair), but
  sets `id = did`.

This is the only addition token needs; the ECDH maths already exists. There is deliberately no
`createFullIdentityForDID` merge helper: the controller kid-stamps its signing half before merging,
so it composes the `FullIdentity` from the signing and agreement pieces itself rather than from a
pre-merged constructor that would have nowhere to stamp the kid.

### 2. Controller: FullIdentity from folded state

The folded `KeyState` already carries `agreement: Array<string>` (the X25519 keys established by
`icp` / `rot`, carried across `rev`) alongside the authority `keys` and the `keyGen` / `keySeq`
position. Both an inception and a rotate derive the agreement key at the **same** `(keyGen, keySeq)`
index as the authority key, so one position locates both.

Extend `identityForState` to, in addition to deriving the authority Ed25519 key:

- derive the X25519 key at `agreementPath(profile, state.keyGen, state.keySeq)`,
- verify its encoded public half is a member of `state.agreement` (the agreement analogue of the
  existing "derived key is one of the current authority keys" check -- fail closed on mismatch),
- return a `FullIdentity` merging the `kid`-stamped signing identity with
  `createKeyAgreementIdentityForDID(did, agreementPrivateKey)`.

The two seed-based entry points -- `createControllerIdentity` and
`createControllerIdentityAsync` -- now return `FullIdentity`.

The `WithKey` forms (`createControllerIdentityWithKey`, `createControllerIdentityWithKeyAsync`)
stay `SigningIdentity`: they receive a single authority private key, not the seed, so they cannot
derive the agreement key. This is documented as a seed-tier capability, not a regression -- the
management / device tier that uses `WithKey` signs but does not decrypt.

### 3. Controller: the keystore utility

A new async function, the one piece consumers call:

```
provideControllerIdentity({
  entry,       // KeyEntry<Uint8Array> -- its bytes are the seed
  profile,     // number
  logStore,    // LogStore
  options?,    // FoldOptions, forwarded for cap-authorised revokes
}): Promise<FullIdentity>
```

Flow:

1. `seed = await entry.provideAsync()` -- generate a fresh seed if the entry is empty, restore the
   stored one otherwise.
2. `did = didFromInception(inceptionEvent(seed, profile))` -- pure function of `(seed, profile)`.
3. `log = await logStore.get(did)`. If `undefined`, bootstrap: `log = [createInception(seed,
   profile)]` and `await logStore.set(did, log)` -- this is the "generate a new identity" path.
4. Return `await createControllerIdentityAsync({ seed, profile, log, options })`, which folds the
   log and yields the `FullIdentity`.

A `KeyStore` caller passes `keyStore.entry(keyID)` as `entry` -- a one-liner, so no separate
store+keyID overload is added.

`entry` is typed `KeyEntry<Uint8Array>`, which `node`, `electron`, `expo`, and `deterministic`
entries satisfy. `browser`'s compound `CryptoKey` record does not, so it does not type-check against
this utility -- the deferral is enforced by the type, not left to documentation.

### 4. Tests

- **Controller unit tests** for `provideControllerIdentity`: generate (empty entry, empty store),
  restore (populated entry and store), the identity after a rotate, and after a revoke, asserting
  the correct authority key and DID each time.
- **Decryption round-trip**: encrypt to the returned identity's DID and decrypt through its
  `agreeKey`, proving the FullIdentity actually decrypts (the gap this design closes).
- **Token unit tests** for `createKeyAgreementIdentityForDID`: `id` equals the supplied DID, and
  `agreeKey` reaches the same shared secret a sender computes with the recipient's X25519 public key.
- **One integration test** driving `provideControllerIdentity` through a real `node` (or
  `deterministic`) `KeyStore`, end to end.
- Keystore-conformance is untouched -- no keystore changes.

## Scope

**In (v1):** the token agreement primitive, the controller FullIdentity path, the
`provideControllerIdentity` utility, and tests. Keystores usable through it as-is: `node`,
`electron`, `expo`, `deterministic`.

**Deferred, with reasons:**

- **`browser`** stores a non-extractable Ed25519 `CryptoKey` plus an agreement secret, not raw seed
  bytes, so it cannot hand back a seed. Supporting it needs a raw-secret entry type in the browser
  package -- its own follow-up.
- **`ledger`** keeps the seed on-device and cannot export it. A Ledger-backed controller uses the
  `WithKey` signing path (the device signs each event), a different seam from this seed utility.
- **Downstream adoption** (bumping `@kokuin/token` to `^0.5.0` and `@kokuin/capability` to `^0.3.0`
  in enkaku / kumiai / kubun / sakui, and auditing kubun's and enkaku's `createCapability` call
  sites for the now-mandatory `exp` and the delegation depth cap) is a separate checklist, not part
  of this plan.

## Non-goals

- No change to how `did:key` identities are produced by any keystore.
- No `did:peer:4` keystore support (no consumer needs it; YAGNI).
- No decryption on the `WithKey` (management-tier) path.
- No new publishable package.
