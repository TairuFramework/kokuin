# KeyStore Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> This plan is split across files. Read this one first, then work the task files **in order** — each assumes the ones before it have landed.

**Goal:** Make `KeyStore`/`KeyEntry` a contract the six keystore backends can actually honor, give every backend a single `provideIdentity(keyID)` entry point, and close the cross-process key-loss race behind an opt-in `lockPath`.

**Architecture:** `@kokuin/token` owns the contract (`KeyEntry` / `MutableKeyEntry` / `KeyStore`) plus an executable, framework-agnostic conformance suite that every backend runs. Each backend implements `IdentityProvider<T>` as a store method and drops its free `provideFullIdentity` functions. Node and electron gain an optional file mutex via `@sozai/lock`. Browser moves off ES256 to non-extractable Ed25519 + X25519.

**Tech Stack:** TypeScript, pnpm workspaces, vitest, `@noble/curves`, `@sozai/lock`, `@napi-rs/keyring` (node), `electron-store` + `safeStorage` (electron), `expo-secure-store` (expo), WebCrypto + IndexedDB (browser).

**Spec:** `docs/superpowers/specs/2026-07-13-keystore-contract-design.md` — read it before starting. It records nine decisions; this plan implements them.

## Task files

| File | Tasks | Deliverable |
|---|---|---|
| [01-token-contract.md](01-token-contract.md) | 1 | `KeyEntry` / `MutableKeyEntry` / `KeyStore` + the conformance suite |
| [02-token-peer4-kem.md](02-token-peer4-kem.md) | 2 | `did:peer:4` identities become encryptable; `did:key` become decryptable |
| [03-deterministic.md](03-deterministic.md) | 3 | HD: `KeyEntry` only, keyID round-trip, hardened paths |
| [04-node.md](04-node.md) | 4–5 | `MutableKeyEntry` + `IdentityProvider`, then opt-in `lockPath` |
| [05-electron.md](05-electron.md) | 6–7 | `Uint8Array` keys, pollution guard, `IdentityProvider`, then `lockPath` |
| [06-expo.md](06-expo.md) | 8 | Object literal → real store class with a cached `entry()` and a lock |
| [07-browser.md](07-browser.md) | 9–11 | ES256 → non-extractable Ed25519 + X25519, yielding `FullIdentity` |
| [08-ledger.md](08-ledger.md) | 12 | Document identity-only conformance; pin it with a type test |
| [09-e2e-node.md](09-e2e-node.md) | 13 | Two real processes racing a real Secret Service |
| [10-release.md](10-release.md) | 14 | Changesets, READMEs, full-repo verification |

**Order matters.** Task 1 defines the contract every backend then implements. Tasks 3–11 each break the repo-wide `build:types` until the last of them lands, so every commit up to and including Task 11 uses `--no-verify`; Task 14 is where the whole repo goes green again.

## Global Constraints

- **pnpm only.** An `rtk` shim intercepts `pnpm run <script>` — invoke tools directly (`pnpm exec vitest run`, `pnpm exec biome check`) or use `rtk proxy pnpm run <script>`.
- **Conventions (kigu):** `type` not `interface`; `Array<T>` not `T[]`; never `any`; capital `ID` / `HTTP` / `JWT` / `DID` in identifiers; ES `#fields` in classes, never `private` / `readonly` modifiers. `readonly` on **type literal members is allowed and stays** (spec decision 8).
- **Never edit `lib/`** — it is generated.
- **Cross-repo deps** (`@sozai/*`) are published `^` ranges via the pnpm catalog in `pnpm-workspace.yaml`, **never** `workspace:`. Intra-repo deps (`@kokuin/*`) are `workspace:^`.
- **Breaking changes are permitted** (spec decision 1). All packages are pre-1.0. `@enkaku` / `@kumiai` are updated as a follow-up, not here.
- **Per-package commands** (run from the package directory):
  - unit tests: `pnpm exec vitest run`
  - type tests: `pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json`
- **Repo-wide:** lint with `pnpm exec biome check --write ./packages` from the repo root.
- The pre-commit hook runs biome on staged files and `build:types` across all packages. A commit that does not type-check will be rejected — hence the `--no-verify` noted above.
- **Every published package that changes needs a changeset** (Task 14). Do not add them per-task.

## What the backends look like when this is done

| Package | `PrivateKeyType` | Storage facet | Identity |
|---|---|---|---|
| token | — | defines the contract | — |
| deterministic | `Uint8Array` | `KeyEntry` (derived — no set/remove) | `IdentityProvider<FullIdentity>` |
| node | `Uint8Array` | `MutableKeyEntry` + opt-in `lockPath` | `IdentityProvider<FullIdentity>` |
| electron | `Uint8Array` | `MutableKeyEntry` + opt-in `lockPath` | `IdentityProvider<FullIdentity>` |
| expo | `Uint8Array` | `MutableKeyEntry` | `IdentityProvider<FullIdentity>` |
| browser | `StoredKeyRecord` | `MutableKeyEntry` | `IdentityProvider<FullIdentity>` + `provideSigningIdentity` |
| ledger-device | — | **neither** — the key never leaves the device | `IdentityProvider<FullIdentity>` |
