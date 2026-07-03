# Security-model documentation

**Status:** backlog
**Origin:** `completed/2026-07-02-audit.complete.md` (Cross-cutting theme 3)

## Context

For an auth layer, all READMEs are install-only stubs — there is no security-model
documentation. Consumers need to understand the guarantees and pitfalls before depending on
kokuin. Best done after the security fixes land, so the docs describe the corrected
behaviour.

## Work

### Write the security model

All READMEs are install-only stubs. Document, per package where relevant:

- Non-extractable P-256 (browser) vs raw Ed25519 in the OS keyring (node) — different threat
  models for the same keyID.
- The `alg:none` pitfall and the requirement to check `isVerifiedToken` after `verifyToken`.
- Audience (`aud`) enforcement expectations.
- Seed retention in memory (deterministic HD).

## Out of scope

- The KeyStore/KeyEntry contract API doc (JSDoc + reconciliation) — see
  `next/2026-07-02-keystore-contract-and-adversarial-tests.md`. This item is the prose
  security model, not the API contract.
- The actual `alg:none` / `aud` code fixes — see the token/capability `next/` items.
