# did:kokuin keystore-identity — follow-ups

Deferred from the completed keystore-identity work (see
`docs/agents/plans/completed/2026-08-16-controller-keystore-identity.complete.md`). `provideControllerIdentity`
resolves a `did:kokuin:` `FullIdentity` from any raw-byte `KeyEntry<Uint8Array>` — v1 covers the
`node`, `electron`, `expo`, and `deterministic` keystores. The items below extend reach or adopt the
new surface downstream. None blocks the shipped work.

## 1. Browser keystore — raw-secret entry support

`@kokuin/browser` stores a non-extractable Ed25519 `CryptoKey` plus an agreement secret, not raw seed
bytes, so it cannot hand back a seed and does not type-check against `provideControllerIdentity`
(`entry: KeyEntry<Uint8Array>`). Supporting it needs a raw-secret entry type in the browser package —
its own follow-up. The deferral is currently enforced by the type, not by documentation.

## 2. Ledger keystore — WithKey decryption path

`@kokuin/ledger-device` keeps the seed on-device and cannot export it, so the seed utility does not
apply. A Ledger-backed controller uses the `WithKey` signing path (the device signs each event),
which today returns a `SigningIdentity` only — no decryption. A decryption path for the management /
device tier is a different seam from the seed utility and was intentionally left out.

## 3. Downstream adoption of the new token / capability surface

Bump `@kokuin/token` to `^0.5.0` and `@kokuin/capability` to `^0.3.0` in enkaku / kumiai / kubun /
sakui, and audit kubun's and enkaku's `createCapability` call sites for the now-mandatory `exp` and
the delegation depth cap. This is a separate cross-repo checklist, gated on the token / capability
release actually publishing.
