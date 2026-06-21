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

- **@kokuin/token** — Core identity and token primitives: `randomIdentity`, `createFullIdentity`, `signToken`, `verifyToken`, `encryptToken`, `decryptToken`, `wrapEnvelope`, `unwrapEnvelope`. The `KeyStore`/`KeyEntry` contract types also live here.
- **@kokuin/capability** — Capability-based authorization built on `@kokuin/token`: `createCapability`, `checkCapability`, `checkDelegationChain`, revocation helpers.
- **@kokuin/node** — Node.js keystore backed by OS credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service). Exports `NodeKeyStore`, `provideFullIdentityAsync`.
- **@kokuin/browser** — Browser keystore backed by IndexedDB / Web Crypto (ES256, non-exportable). Exports `BrowserKeyStore`, `provideSigningIdentity` (signing only — no decryption).
- **@kokuin/expo** — React Native / Expo keystore backed by `expo-secure-store`. Exports `ExpoKeyStore`, `provideFullIdentityAsync`.
- **@kokuin/electron** — Electron keystore using `safeStorage` + `electron-store`. Exports `ElectronKeyStore`, `provideFullIdentityAsync` (main process only).
- **@kokuin/deterministic** — SLIP-0010 Ed25519 HD derivation from a seed phrase. Exports `HDKeyStore`, `derivePrivateKey`, `resolveDerivationPath`. No `provide*` helper — build identities from derived private keys via `createFullIdentity` in `@kokuin/token`.
- **@kokuin/ledger-device** — Ledger hardware wallet integration. Exports `createLedgerIdentityProvider` (an `IdentityProvider` — not a keystore class); private keys never leave the device.
