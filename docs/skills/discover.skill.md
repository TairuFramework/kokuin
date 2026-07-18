---
name: kokuin:discover
description: Explore kokuin identity capabilities by domain
---

# Kokuin Identity Discovery

Kokuin is the identity layer — DID-based keys, signed tokens, JWE encryption, and capability-based delegation. Use the sections below to find the right skill or package for your task.

## By Domain

### Authentication & Keys

Tokens, identities, encryption, keystores. Covers the full identity lifecycle: generating DID-based key pairs, signing and verifying JWT-like tokens, ECDH-ES message encryption (JWE), and per-environment keystore implementations (Node.js, browser, Expo, Electron, HD derivation, Ledger hardware).

→ `/kokuin:auth`

### Capabilities & Delegation

Scoped permissions, delegation chains, revocation. Covers capability tokens built on top of `@kokuin/token`: issuing root capabilities, delegating narrowed permissions to subordinate keys, verifying delegation chains, and revoking tokens via a pluggable backend.

→ `/kokuin:capability`

## Package Overview

- **@kokuin/token** — Core identity and token primitives: `randomIdentity`, `createFullIdentity`, `signToken`, `verifyToken`, `encryptToken`, `decryptToken`, `wrapEnvelope`, `unwrapEnvelope`. The contract types also live here: `KeyStore`, `KeyEntry` (read/provide) and `MutableKeyEntry` (adds write/delete), plus `IdentityProvider`.
- **@kokuin/capability** — Capability-based authorization built on `@kokuin/token`: `createCapability`, `checkCapability`, `checkDelegationChain`, revocation helpers.
- **@kokuin/node** — Node.js keystore backed by OS credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service). Exports `NodeKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
- **@kokuin/browser** — Browser keystore backed by IndexedDB / Web Crypto (non-extractable Ed25519 + derived X25519). Exports `BrowserKeyStore`; `store.provideIdentity(keyID)` returns a `FullIdentity`, `store.provideSigningIdentity(keyID)` accepts legacy ES256 records signing-only.
- **@kokuin/expo** — React Native / Expo keystore backed by `expo-secure-store`. Exports `ExpoKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
- **@kokuin/electron** — Electron keystore using `safeStorage` + `electron-store` (main process only). Exports `ElectronKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
- **@kokuin/deterministic** — SLIP-0010 Ed25519 HD derivation from a seed phrase. Exports `HDKeyStore`, `HDKeyEntry`, `derivePrivateKey`, `resolveDerivationPath`; call `store.provideIdentity(keyID)` for a `FullIdentity` — async-only, there is no sync twin.
- **@kokuin/ledger-device** — Ledger hardware wallet integration. Exports `createLedgerIdentityProvider` (an `IdentityProvider<FullIdentity>` — not a keystore class); call `provider.provideIdentity(keyID)` for a `FullIdentity`. Private keys never leave the device.
