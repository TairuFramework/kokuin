# Kokuin stores follow-ons

**Status:** backlog
**Origin:** `completed/2026-10-07-kokuin-stores.complete.md` (items deferred from task and final
reviews; none block merge).

## Context

`@kokuin/store-controller` and `@kokuin/store-delegation` port kubun's stores onto hozon. The
items below were judged safe to merge without fixing. Each one is either hardening or work that
belongs to kubun adoption.

## Work

### Adoption (when kubun moves onto these stores)

- **Legacy Postgres `hlc` collation.** Under `tablePrefix: 'kubun'`, `0-init` is already recorded,
  so kubun's locale-collated `hlc` columns are never altered. SQL `>` and JS `<=` can then disagree
  on the winner. Either ship an idempotent Postgres-only `1-hlc-collation` migration
  (`ALTER COLUMN hlc TYPE text COLLATE "C"` on `<prefix>_delegation_tokens` and
  `<prefix>_revoked_capabilities`), or make adopters run it. It is documented in
  `docs/reference/stores.md`.
- **HLC helper.** Once the HLC package moves to sozai, add a stamp helper and a stricter `hlc`
  type, and use it as a test-only dev dependency.
- **Consumer contract on `cap.iat`.** Pending-purge safety needs `cap.iat ≤ now + 3600`. kokuin does
  not enforce this today. See also `backlog/2026-08-04-capability-iat-is-optional.md`.

### Hardening

- **Non-string capability `jti`.** `createRevocationChecker` compares with `===`. A capability
  minted with a non-string `jti` never matches its revocation. Only an issuer violating the types
  can trigger this. Fix: reject or skip a non-string `jti` at the top of the checker.
- **`VerifiedRevocationError`.** It drops the `TokenRevokedError` cause. It also has no static
  `brand` and no `isVerifiedRevocationError` guard, unlike `TokenRevokedError`, and consumers
  matching across duplicated package copies need the guard.
- **Fragment asymmetry in fault gating.** `isOwnIssuer` strips `#fragment` from the resolver
  argument but not from `token.payload.iss`. This fails closed, but with the wrapped error instead
  of the original fault.
- **Type casts.** `adapter.encodeTimestamp(...) as number` in both stores is a type lie on
  Postgres, where it is a string. `decodeSignedToken` casts unchecked JSON to `SignedToken<P>`.

### Test gaps

- No case re-stores an equal `hlc` with different content. Mutating JS `<=` to `<` passes every
  test. Add one per table: expect `false` and an unchanged row.
- The floored pending row is only checked on the late side. Add a survival check at
  `floored + TTL + grace`.
- No test proves `isTokenRevokedError` matches by brand on a foreign-copy object.
- Postgres per-adapter isolation in the integration harness is structural and no test enforces
  it.
- Tidy-ups:
  - near-duplicate floor tests and corrupt-record tests;
  - `store-controller.test.ts` hard-codes `hozon_controller_logs`;
  - `db.close()` followed by `cleanup()` double-closes.
