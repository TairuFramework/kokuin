# Security-model documentation

**Status:** backlog
**Origin:** `completed/2026-07-02-audit.complete.md` (Cross-cutting theme 3)

## Context

For an auth layer, all READMEs are install-only stubs — there is no security-model
documentation. Consumers need to understand the guarantees and pitfalls before depending on
kokuin. Best done after the security fixes land, so the docs describe the corrected
behaviour.

**Blocked on (2026-08-03 triage):** `next/2026-08-03-peer4-revocation-records-are-unverifiable.md`.
Every other audit fix has landed — capability authorization, keystore correctness, firmware
consent, token verification. That one is the last open item that changes behaviour this
document would describe: it decides when a `did:peer:4` signer embeds the long form in `iss`,
and therefore which tokens a recipient can verify at all. Write the prose after it settles.

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
