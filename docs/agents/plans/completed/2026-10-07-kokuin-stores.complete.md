# Kokuin persistence stores (`@kokuin/store-controller`, `@kokuin/store-delegation`) — completed

**Status:** complete
**Date:** 2026-10-07
**Branch:** `feat/stores` (spec `1ea9351` .. `f50cec8`). Build 16/16, test 66/66, biome clean,
`test:integration` 254 passed / 1 skipped on SQLite and Postgres.
**Staging:** not merged, not published. The two store packages are at `0.1.0`, never published, and
have no release intent: an intent would bump them to `0.2.0`. `store-controller` is absent from
`pnpm change status`, so check at release time that `publish -r` picks it up. `@kokuin/token` and
`@kokuin/capability` have minor intents.

## Goal

Port kubun's controller-log store and delegation/revocation store into kokuin, built on hozon
(`@hozon/db`, `@hozon/adapter`). Then any stack app that persists `did:kokuin:` controller logs or
delegated capabilities and their revocations can register them, not only kubun. Removing kubun's
own copies and adopting these stores is out of scope.

## Why kokuin, not hozon

kokuin owns the interfaces the stores implement: `LogStore` (`@kokuin/controller`) and
`RevocationBackend` (`@kokuin/capability`). An interface change ships with its store in one release.
The delegation store holds auth-domain logic (DID normalization, issuer-scoped revocation rows,
the revocation checker), and hozon stays domain-neutral. There is no cycle: hozon depends only on
`@sozai/*`, and only the two store packages (plus the private integration workspace) depend on
hozon. They import kysely types and `sql` through `@hozon/db`; `kysely` itself is only a
`store-delegation` dev dependency, for the test-only `Migrator`.

## What was built

- **`@kokuin/token`:** `decodeSignedToken`, an unverified parse that keeps the original
  `<header>.<payload>` as `data`, so a later verifier checks the original signed bytes.
- **`@kokuin/capability`:**
  - `TokenRevokedError` and `isTokenRevokedError`. The error is branded, keeps the message
    `Token revoked: <jti>`, and keeps `cause` on the denied-key path.
  - The `RevocationClaims` export.
  - `createRevocationChecker` hardening:
    - a record counts as evidence only if its payload is an object with a string `iss`,
      `rev === true` and `jti` equal to the capability's `jti`;
    - before this, it compared only `iss`, so any token an issuer signed, filed under any `jti`,
      revoked that issuer's capability (a gap inherited from kubun).
- **`@kokuin/store-controller`:**
  - a hozon `StoreDefinition` named `controller`, table `controller_logs`;
  - `ControllerStoreAPI = LogStore & { getObservedAt }`;
  - `set` stays plain last-writer-wins. Its doc comment says untrusted peer logs must pass the
    resolver's `history` guard first.
- **`@kokuin/store-delegation`:**
  - a hozon `StoreDefinition` named `delegation`, tables `delegation_tokens` and
    `revoked_capabilities`;
  - every kubun method, with kubun's constants;
  - `createDelegationRevocationBackend`, `createDelegationRevocationChecker` and
    `VerifiedRevocationError`.
- **`tests/integration` (`integration-tests`, private):**
  - runs both stores' shared cases on Postgres (a fresh database per adapter) and on file-backed
    SQLite;
  - pins the legacy `tablePrefix: 'kubun'` names through catalog queries, `COLLATE "C"`, and jsonb
    round-trips;
  - a Postgres concurrency test cycles write order and fails when the `hlc` guard is removed.
- **Docs:** `docs/reference/stores.md`, store sections in the capability/auth/discover skills,
  `architecture.md`, and an AGENTS.md guardrail.

## Key design decisions

- **Naming.** Tables use logical names, prefixed by hozon's `TablePrefixPlugin` (default `hozon_`).
  Index and constraint names are `${tablePrefix}_…`. Migration ID `0-init` and store names
  `controller`/`delegation` are kept. Under `tablePrefix: 'kubun'`, the data-table and
  migration-bookkeeping names match kubun's; the index and primary-key names do not.
- **Transactions.**
  - `addDelegationToken` and `addRevocation` pre-read and upsert inside `withStoreTransaction`,
    which joins an enclosing transaction. No store method calls `.transaction()`.
  - The pre-read takes no lock, so their returned `boolean` is documented as an approximate change
    signal. The SQL `hlc` arbiter keeps the stored row correct.
  - No statement binds more than 9 parameters (limit 500).
- **Revocation GC.**
  - Removed: kubun's sampled 1% purge inside `addDelegationToken` (a caught failure still aborted
    the enclosing Postgres transaction), along with `REVOCATION_GC_SAMPLE_RATE` and the logger.
    Consumers schedule `purgeExpiredRevocations` and `purgeDeadPendingRevocations` themselves.
  - Grace handling: `graceSeconds` is optional and defaults to 30 days. A value that is not a
    non-negative safe integer throws `RangeError`, because a negative grace un-revokes.
  - Pending rows are purged at `stored_revoked_iat + MAX_CAP_TTL_SECONDS + grace`, where a future
    `revoked_iat` is floored to `write_time + 3600`.
  - Purge safety rests on consumer contracts the store cannot see:
    - capability lifetime ≤ `MAX_CAP_TTL_SECONDS`, with `iat` required;
    - `iat ≤ now + drift`;
    - grace covers the consumer's `clockTolerance`.

    These are documented, not enforced.
  - A verified row whose `cap_exp` is null is never purged (kubun parity, documented).
- **HLC ordering.**
  - `hlc` is an opaque, caller-supplied string. Byte-wise (ASCII) order must match causal order.
  - SQL `>` and JS `<=` must agree, so the migration adds `COLLATE "C"` on Postgres.
  - A legacy kubun Postgres database already has `0-init` recorded and keeps its locale collation.
    Adopters must `ALTER … COLLATE "C"` both `hlc` columns. This is documented, with no migration
    added, because adoption is out of scope.
  - No HLC package dependency: local-only consumers may pass any increasing string of the format,
    and syncing consumers need a real HLC (`@kubun/hlc` today).
- **Revocation checker.** `@kokuin/capability` is the only verifier. The store wrapper does no
  verification of its own, which fixes kubun's wrapper:
  - kubun's wrapper omitted `historic: true`, so revocations by a rotated issuer read as "not
    revoked";
  - it also bypassed the denied-key verdict.

  The wrapper's own rules:
  - **Backend.** `get(jti, issuer)` is issuer-scoped. It returns `undefined` for a record that does
    not decode, whose header or payload is not a plain object, or whose `jti` differs.
  - **Fault tracking.** A dependency fault rethrows even when capability's checker returns
    normally ("a resolver that cannot answer must never read as not revoked"). Faults are recorded
    only from the store read and from resolver calls for the capability's own issuer, for two
    reasons:
    - a record naming another issuer cannot revoke, so a fault while resolving it hides nothing;
    - counting such faults would let a planted record deny every check.
  - **Key-not-found.** `IssuerKeyNotFoundError` is an answer that capability adjudicates (its
    denied-key path depends on it), not a fault. So the method resolver's `loadLog` must be fresh:
    a revocation signed with a key the local log has not yet seen reads as "not revoked".
  - **Proof of revocation.** `TokenRevokedError` maps to `VerifiedRevocationError`. The wrapper
    never matches on the message.

## Lessons

- Every security defect on this branch was found by building the attack, not by reading the diff:
  the jti/rev binding gap, the null-payload `TypeError`, the planted foreign-record DoS, and a
  concurrency test that passed without the guard it pinned.
- Two came from following the plan literally: "record every thrown error" broke denied-key
  revocation, and fixed write order hid last-writer-wins.

## Follow-on work

- `next/2026-07-02-ci-release-gating.md`: run the store integration suite in CI.
- `backlog/2026-10-07-kokuin-stores-follow-ons.md`: hardening and adoption items deferred from
  review.
