# KeyStore/KeyEntry contract and adversarial tests

**Status:** next
**Origin:** `completed/2026-07-02-audit.complete.md` (Cross-cutting themes 1 & 2, Medium: node e2e, nit: readonly)

## Context

Per the audit's own note, this is the repo's highest-leverage item — specifying the central
KeyStore/KeyEntry contract and adding adversarial tests "would have caught most of the
above." The concrete bug fixes are tracked separately; this item is the contract + test
foundation that prevents regressions.

## Work

### Specify and reconcile the KeyStore/KeyEntry contract (Theme 1)

`packages/token/src/keystore.ts` has zero JSDoc and implementations diverge:

- HD `setAsync` throws while browser/node store.
- HD `removeAsync` is a silent no-op.
- Null semantics differ across implementations.
- Identity-provider argument order flips: browser `(keyID, store)` vs node `(store, keyID)`.
- Browser yields ES256 `SigningIdentity`; node/HD yield Ed25519 `FullIdentity` for the same
  keyID.

Document the contract (methods, null semantics, argument order, identity type) and reconcile
the implementations to it.

### Adversarial-input test suite (Theme 2)

Test suites are happy-path; mocks hide real bugs. electron never tests two keys in one store
(masks Critical #4); the node mock ignores the service arg; browser `open` is fully mocked
out. Add adversarial tests: `alg:none`, tampered delegation chains, prefix permissions,
non-hardened HD paths, non-base64 credentials, two-keys-in-one-store.

### No e2e coverage for `@kokuin/node` (Medium)

The only keystore without a `tests/*` app. Add one.

### Convention nit

Decide whether the "never `readonly`" rule covers type-literal modifiers or only class
fields; `readonly` appears on type members in `packages/token/src/keystore.ts:2` and
`identity.ts:16`. Apply the decision here since this item touches the contract types.

## Out of scope

- The concrete keystore bug fixes — see `next/2026-07-02-keystore-correctness-fixes.md`.
- Security-model prose documentation — see `backlog/2026-07-02-security-model-docs.md`.
