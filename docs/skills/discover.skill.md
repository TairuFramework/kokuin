---
name: kokuin:discover
description: Explore kokuin identity capabilities by domain
---

# Kokuin Identity Discovery

Kokuin is the identity layer — DID-based keys, signed tokens, JWE encryption, and capability-based delegation. Use the sections below to find the right skill or package for your task.

## By Domain

### Authentication & Keys

Tokens, identities, encryption, keystores. Covers the full identity lifecycle: generating DID-based key pairs, signing and verifying JWT-like tokens, ECDH-ES message encryption (JWE), rotating a `did:kokuin:` controller's keys through a folded event log, and per-environment keystore implementations (Node.js, browser, Expo, Electron, HD derivation, Ledger hardware).

→ `/kokuin:auth`

### Capabilities & Delegation

Scoped permissions, delegation chains, revocation. Covers capability tokens built on top of `@kokuin/token`: issuing root capabilities, delegating narrowed permissions to subordinate keys, verifying delegation chains, and revoking tokens via a pluggable backend.

→ `/kokuin:capability`

### Profile DIDs (`did:kokuin:`)

A self-certifying DID whose key set rotates through a key event log instead of living in the identifier. Covers inception and derivation, rotate / revoke / reset, the fold and its key state, branch selection and duplicity, and the resolver that plugs the method into token, jwe and capability.

→ [reference/controller.md](../reference/controller.md), and [reference/security.md](../reference/security.md) for the guarantees, the assumptions and the rules a consumer must follow. Read the second before depending on the first.

### Persistence

Hozon-backed stores for `did:kokuin:` controller logs and for delegation tokens and revocations, with a revocation checker over `@kokuin/capability`. Covers registration, tables, the `hlc` ordering contract, purge scheduling and the checker's fail-closed behaviour.

→ [reference/stores.md](../reference/stores.md)

## Package Overview

- **@kokuin/token** — Core identity and token primitives: `randomIdentity`, `createFullIdentity`, `signToken`, `verifyToken`, `stringifyToken`. The contract types also live here: `KeyStore`, `KeyEntry` (read/provide) and `MutableKeyEntry` (adds write/delete), plus `IdentityProvider`.
- **@kokuin/jwe** — JWE message encryption split out of `@kokuin/token`: `createTokenEncrypter`, `createTokenEncrypterAsync`, `encryptToken`, `decryptToken`, `deriveSharedSecret`, `deriveSharedSecretAsync`, `wrapEnvelope`, `unwrapEnvelope`. The async siblings resolve recipients through a registered `DIDMethodResolver` (e.g. `did:kokuin:`); the sync entry points only handle self-contained DIDs (`did:key`, `did:peer:4`).
- **@kokuin/controller** — `did:kokuin:` controller key event log: a root chain (`createInception`, `createRotate` — every rotate carries a state snapshot, built with `snapshotOf` — and `createReset`, blind or with a snapshot) and a management tier merged per epoch (`createAdd`, `createRenew`, `createRemove`, `createRevoke`, signed by root or by a management member). `foldLog(did, { chain, events })` (sync, total, clock-free), `epochHeads` (the parents a new epoch event should name), `resolveBranches`, `mergeLogs`, `pruneLog`, `authoritativeLog`, `createControllerResolver` (a `DIDMethodResolver` with `resolveMember` and `frozen()`, injected into `@kokuin/jwe`'s async entry points, `@kokuin/token`'s `resolveIssuer`/`resolveIssuerWithDoc`, or `verifyToken`'s `methods` option; takes an optional `history` `LogStore` that refuses a chain behind one already seen and never forgets a current-epoch event), `createControllerIdentity` / `createControllerIdentityWithKey` (a `SigningIdentity` issuing as the profile DID — prefer the key form on any daily path, since the seed form needs the root seed), `enumerateProfiles`, `handleForDID`.
- **@kokuin/capability** — Capability-based authorization built on `@kokuin/token`: `createCapability` (with `member` for a grant issued by a `did:kokuin:` management member), `checkCapability`, `checkDelegationChain`, `assertMemberRoot` and the `MEMBER_GRANT_*` reasons, `DEFAULT_MEMBER_GRANT_LIFETIME`, revocation helpers.
- **@kokuin/node** — Node.js keystore backed by OS credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service). Exports `NodeKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
- **@kokuin/browser** — Browser keystore backed by IndexedDB / Web Crypto (non-extractable Ed25519 + derived X25519). Exports `BrowserKeyStore`; `store.provideIdentity(keyID)` returns a `FullIdentity`, `store.provideSigningIdentity(keyID)` accepts legacy ES256 records signing-only.
- **@kokuin/expo** — React Native / Expo keystore backed by `expo-secure-store`. Exports `ExpoKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
- **@kokuin/electron** — Electron keystore using `safeStorage` + `electron-store` (main process only). Exports `ElectronKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
- **@kokuin/deterministic** — SLIP-0010 Ed25519 HD derivation from a seed phrase. Exports `HDKeyStore`, `HDKeyEntry`, `derivePrivateKey`, `resolveDerivationPath`; call `store.provideIdentity(keyID)` for a `FullIdentity` — async-only, there is no sync twin.
- **@kokuin/ledger-device** — Ledger hardware wallet integration. Exports `createLedgerIdentityProvider` (an `IdentityProvider<FullIdentity>` — not a keystore class); call `provider.provideIdentity(keyID)` for a `FullIdentity`. Private keys never leave the device.
- **@kokuin/store-controller** — Hozon store for `did:kokuin:` event logs: `controllerStoreDefinition`, `getControllerStore`, `createControllerStore`; implements `LogStore` (`get`, an atomic `merge`) plus `getObservedAt`.
- **@kokuin/store-delegation** — Hozon store for delegation tokens and revocations: `delegationStoreDefinition`, `getDelegationStore`, `createDelegationRevocationChecker` (a `VerifyTokenHook`), `createDelegationRevocationBackend`, `purgeExpiredRevocations` / `purgeDeadPendingRevocations`.
