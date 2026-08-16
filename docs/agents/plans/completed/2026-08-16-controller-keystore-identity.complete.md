# did:kokuin FullIdentity from a keystore — completed

**Status:** complete
**Date:** 2026-08-16
**PR:** TairuFramework/kokuin#14 (branch `controller-keystore-identity`)

## Goal

Give consumers a high-level way to obtain a ready `did:kokuin:` **FullIdentity** (signing plus
decryption) from an existing keystore, without teaching any keystore about controllers. A keystore
stores the seed; a single utility folds the log and hands back a `FullIdentity`, generating a fresh
identity on first use and restoring an existing one afterwards.

## What was built

- **`@kokuin/token` — `createKeyAgreementIdentityForDID(id, x25519PrivateKey)`.** A DID-bound
  key-agreement identity, the agreement-half counterpart of `createSigningIdentityForDID`. It runs
  ECDH directly on a raw X25519 scalar and binds `id` to the supplied DID.
- **`@kokuin/controller` — `FullIdentity` from folded state.** `identityForState` now derives the
  X25519 key at the current `(keyGen, keySeq)`, verifies its encoded public half is a member of the
  folded `state.agreement` set (fail closed), and returns a `FullIdentity`. The seed-based entry
  points `createControllerIdentity` / `createControllerIdentityAsync` return `FullIdentity`.
- **`@kokuin/controller` — `provideControllerIdentity({ entry, profile, logStore, options? })`.** The
  one function consumers call: reads the seed from a `KeyEntry<Uint8Array>`, computes the DID from
  `(seed, profile)`, loads-or-bootstraps the log from a `LogStore`, and folds it into the identity.
  A `didFor(seed, profile)` helper computes the DID without signing an inception, so the restore path
  does no wasted signing.

## Key design decisions (rationale preserved)

1. **Full FullIdentity now.** The controller gained its first key-agreement / decryption path, so the
   utility returns a true `FullIdentity` rather than a signing-only stand-in. Every inception already
   carried X25519 agreement keys (`ka`) that nothing consumed before this.
2. **A `KeyEntry`'s raw private-key bytes are the controller seed.** `provideAsync()` already gives
   generate-if-absent / restore-if-present for raw-byte keystores, so no new storage type was needed.
   `keyID` names the seed; `profile` selects identities under it.
3. **LogStore-backed, generate and restore in one call.** The utility loads the log from a `LogStore`
   and bootstraps a fresh inception when none exists, serving both a new and an existing identity.
4. **The utility lives in `@kokuin/controller`.** The controller already depends on `@kokuin/token`
   (which owns `KeyStore` / `KeyEntry`) and defines `LogStore`, so no new package and no cyclic
   dependency (`controller → token`, `controller → jwe → token`, `controller → deterministic → token`
   all stay acyclic).
5. **The agreement key is an independent X25519 keypair at `agreementPath`**, NOT the Montgomery form
   of the authority Ed25519 key — which is why the token addition takes a raw X25519 scalar. Both an
   inception and a rotate derive the agreement key at the **same** `(keyGen, keySeq)` index as the
   authority key, and a revoke carries the agreement set forward, so one position locates both. The
   derivation index and the folded `state.agreement` set were verified aligned across icp / rot / rev
   / reset.
6. **The `WithKey` (management-tier) entry points stay `SigningIdentity`.** They receive a single
   authority private key, not the seed, so they cannot derive the agreement key. This is a seed-tier
   capability, not a regression — the management / device tier signs but does not decrypt.

## Verification

Token: real two-party ECDH agreement test. Controller: FullIdentity assertion; a fail-closed
agreement-membership test built from a legitimately-signed inception carrying a foreign agreement key
(so the membership guard is the specific failure, not a signature rejection); generate / restore /
profile-split / rotate / revoke coverage; `options` forwarding proven non-tautologically (a
capability-authorised-revoke log resolves with `options` and fails "needs a verifier" without). End
to end: a JWE encrypted to the agreement key decrypts through the resolved `FullIdentity`, and a real
`@kokuin/deterministic` `HDKeyStore` drives the utility. A clean build confirms no dependency cycle.
Full controller suite: 579/579.

Reviewed per task (spec + quality) and once whole-branch; two Minor findings (restore-path signing,
untested `options` forwarding) fixed and re-reviewed.

## Release

Minor intents recorded: `@kokuin/token` (→ 0.5.0) and `@kokuin/controller` (records the API; holds at
0.1.0, still unpublished). No versioning applied and nothing published — that stays a separate,
gated step.

## Follow-on work

Deferred, tracked in `docs/agents/plans/backlog/2026-08-16-controller-keystore-identity-followups.md`:
browser raw-secret entry support, ledger `WithKey` decryption, and the downstream range-bump plus
`exp` / delegation-depth audit in enkaku / kumiai / kubun / sakui.
