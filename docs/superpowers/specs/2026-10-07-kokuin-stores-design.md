# Kokuin persistence stores

Status: design approved, pending implementation plan. Branch `feat/stores`.

## Goal

Port kubun's `@kubun/store-controller` and `@kubun/store-delegation` into kokuin as
`@kokuin/store-controller` and `@kokuin/store-delegation`, built on hozon (`@hozon/db`,
`@hozon/adapter`). Any stack app that persists `did:kokuin:` controller logs or
delegated capabilities and their revocations can then register them, not only kubun.

## Why kokuin, not hozon

- kokuin owns the interfaces the stores implement: `LogStore` (`@kokuin/controller`) and
  the revocation backend (`@kokuin/capability`). An interface change ships with its store
  in one release.
- kokuin already hosts implementations of its own contracts (the per-runtime keystores).
- The delegation store holds auth-domain logic: `normalizeDID` folding, issuer-scoped
  revocation rows, and the revocation checker. hozon stays domain-neutral.
- No cycle: hozon depends only on `@sozai/*`. Only these two packages pull in hozon and
  kysely; the rest of kokuin does not.

## Non-goals

- Kubun adoption (removing the kubun packages, registering these stores). Out of scope.
- Schema changes beyond the renames below. Column sets, primary keys and indexes stay
  as in kubun.
- Any dependency on `@kubun/*`, including `@kubun/hlc` (see "HLC ordering contract").

## Packages

### `@kokuin/store-controller`

- Dependencies: `@hozon/adapter`, `@hozon/db`, `@kokuin/controller` (`workspace:^`),
  `kysely`.
- Store name `controller`, exported as `CONTROLLER_STORE`. `controllerStoreDefinition`
  and `getControllerStore(provider)` live in `definition.ts`, following `@hozon/store-blob`.
- Table `controller_logs`: `did` (PK), `log` (JSON array of `SignedEvent`), `created_at`,
  `updated_at`.
- API: `ControllerStoreAPI = LogStore & { getObservedAt(did): Promise<Date | undefined> }`.
  It is typed against `LogStore`, so drift in that interface is a type error.
- `set` stays plain last-writer-wins. The doc comment keeps the warning that untrusted
  (peer) logs must pass the resolver's `authoritativeStates`/`history` guard first; the
  store does not refuse truncated or forked logs.

### `@kokuin/store-delegation`

- Dependencies: `@hozon/adapter`, `@hozon/db`, `@kokuin/capability` and `@kokuin/token`
  (`workspace:^`), `kysely`. No logger dependency (see "Revocation GC").
- Store name `delegation`, exported as `DELEGATION_STORE`. `delegationStoreDefinition` and
  `getDelegationStore(provider)` live in `definition.ts`.
- Tables `delegation_tokens` and `revoked_capabilities`, with the kubun columns, keys and
  indexes. `revoked_capabilities` stays keyed by `(jti, revoker_did)`.
- `createDelegationStore(db, adapter)` matches hozon's `createAPI` signature. The kubun
  third `logger` parameter is removed.
- The API keeps every kubun method: `addDelegationToken`, `getDelegationTokens`,
  `getHeldTokens`, `listIssuedTokens`, `getDelegationTokenByGrantorJTI`,
  `listDelegationTokensByJTI`, `removeDelegationToken`, `addRevocation`,
  `getRevocationByIssuer`, `listRevocations`, `isRevokedBy`, `getHeldRevocations`,
  `markRevocationVerified`, `getPendingRevocationByIssuer`,
  `deletePendingRevocationsFromOtherIssuers`, `purgeExpiredRevocations`, and
  `purgeDeadPendingRevocations`.
- Exported constants keep their values: `MAX_CAP_TTL_SECONDS`,
  `MAX_REVOCATION_FUTURE_DRIFT_SECONDS`, and `REVOCATION_GC_VERIFIED_GRACE_SECONDS`.
- `createDelegationRevocationChecker`, `RevocationClaims` and `VerifiedRevocationError`
  move, with the verify path reconciled (see "Revocation checker"). The error brand
  becomes `@kokuin/store-delegation/VerifiedRevocationError`.
- Every DID crossing the store boundary is still folded through `normalizeDID`.

## Changes from the kubun originals

### Kubun removal

- `@kubun/db` becomes `@hozon/db`; `@kubun/db-adapter` becomes `@hozon/adapter`
  (`Adapter`, `CreatedAtColumn`, `UpdatedAtColumn`).
- `kubun_*` physical table names become logical names. Under
  `HozonDB({ tablePrefix: 'kubun' })` they resolve to the kubun names
  (`kubun_controller_logs`, `kubun_delegation_tokens`, `kubun_revoked_capabilities`).
- Constraint and index names use `${ctx.tablePrefix}_…`, following `@hozon/store-blob`.
  For example, `pk_delegation_tokens` becomes `${ctx.tablePrefix}_delegation_tokens_pkey`
  and `idx_delegation_tokens_jti` becomes `${ctx.tablePrefix}_delegation_tokens_jti_idx`.
- Compatibility under `tablePrefix: 'kubun'` covers data-table names only. Index and
  constraint names differ from kubun's. The migration ID stays `0-init` and the store
  names stay `controller` and `delegation`, so hozon's migration bookkeeping names line
  up. Integration tests assert table, index, constraint and bookkeeping names through
  catalog queries.
- Comments that cite kubun internals (`KubunEngine`, `engine.ts:208`, "kubun's resolver")
  are reworded in generic consumer terms. They keep the rationale.

### Transactions

- `addDelegationToken` and `addRevocation` run their pre-read and upsert inside
  `withStoreTransaction`. It reuses an enclosing transaction, so the kubun reason for
  leaving them unwrapped (nested transactions) no longer applies.
- This does not remove the read/upsert race. The pre-read takes no lock and isolation is
  unchanged, so two concurrent writers on Postgres can both read absence and both return
  `true`. The upsert itself stays correct under the SQL `hlc` arbiter. The returned
  `boolean` is documented as an approximate change signal for emission gating, not an
  exact one.
- No store method calls `.transaction()` directly.
- No statement binds more than 500 parameters. Every current statement binds a fixed,
  small number of parameters; the plan audits each one.

### Revocation GC

The kubun `addDelegationToken` ran a sampled purge (1%) and caught its errors. On
Postgres a failed statement aborts the enclosing transaction, so catching in JS did not
protect the caller, and the store's `Kysely` handle cannot open savepoints. The sampled
sweep is removed, along with `REVOCATION_GC_SAMPLE_RATE` and the logger.

Consumers call `purgeExpiredRevocations` and `purgeDeadPendingRevocations` on their own
schedule. Both are single time-predicate `DELETE`s: atomic, idempotent, and safe to run
concurrently with writes. Their timing is safe while the contracts below hold. Calling
them rarely only grows the table.

Guard: `graceSeconds` becomes optional (`{ graceSeconds?: number }`) and defaults to
`REVOCATION_GC_VERIFIED_GRACE_SECONDS`. Any value that is not a non-negative safe integer
throws `RangeError`: negative, fractional, `NaN`, either infinity, or above
`Number.MAX_SAFE_INTEGER`. A negative grace would delete revocations of still-valid
capabilities, which un-revokes them. A fractional or oversized one breaks the bigint
comparison on Postgres. Both purges compute integer cutoffs the same way.

Pending-purge safety. A pending row is deleted once
`now > stored_revoked_iat + MAX_CAP_TTL_SECONDS + grace`, where
`stored_revoked_iat = min(revoked_iat, write_time + MAX_REVOCATION_FUTURE_DRIFT_SECONDS)`.
The deletion is safe only if the revoked capability can no longer be accepted, which
requires `cap.exp + tolerance ≤ stored_revoked_iat + MAX_CAP_TTL_SECONDS + grace`, where
`tolerance` is the consumer's `clockTolerance`. That holds when the consumer enforces both
of the following on mint and on receive:

- `cap.exp - cap.iat ≤ MAX_CAP_TTL_SECONDS`, with `iat` required;
- `cap.iat ≤ now + MAX_REVOCATION_FUTURE_DRIFT_SECONDS`, which kokuin does not enforce
  today.

A revocation is signed after the capability it names exists, so a genuine
`revoked_iat ≥ cap.iat - drift`. The default 30-day grace covers the drift, the clamping
and the clock tolerance. The store never sees the capability, so these are documented
consumer contracts on both purge methods and in the reference.

Other contracts:

- Run purges outside a caller transaction. On Postgres a failure inside one aborts it.
- A local clock running ahead deletes rows early. The default grace absorbs ordinary skew.

### Revocation checker

The kubun wrapper pre-verifies the stored record with `verifyToken(..., { methods })`.
That call omits `historic: true` and returns `undefined` on `isIssuerKeyNotFoundError`, so
after a `did:kokuin:` issuer rotates, its earlier revocations read as "not revoked". It
also bypasses `@kokuin/capability`'s denied-key verdict (`namesADeniedKey`).

The ported checker must use the same verify options as `@kokuin/capability`'s revocation
checker (`methods`, `resolver`, `cache`, `historic: true`). It must not short-circuit
before capability's denied-key handling runs. The implementation either exports a
shared helper from `@kokuin/capability` or restructures the wrapper so that only
capability verifies the record, while the wrapper keeps its dependency-fault tracking.
The plan picks one after reading both. The wrapper's observable contract is unchanged:
a store or resolver fault rethrows, a proved revocation raises `VerifiedRevocationError`,
and a corrupt record is not evidence.

### HLC ordering contract

No code depends on an HLC package. Both tables store `hlc` as an opaque string.
Last-writer-wins compares it with SQL `>` and JS `<=`. The column contract, documented on
the insert types and in the reference: `hlc` must be a string whose byte-wise
lexicographic order matches causal order. A fixed-width serialized HLC satisfies this.

SQL and JS must agree on the ordering. SQLite's default `BINARY` collation is byte-wise.
On Postgres, the default collation can be locale-sensitive, so the migration adds
`COLLATE "C"` to both `hlc` columns when `ctx.kind === 'postgres'`. Tests use literal
fixed-width strings, including stamps with equal time and counter but different node
IDs (mixed case, digits and punctuation), and assert that SQL and JS pick the same
winner on both backends. When the HLC package lands in sozai, it may become a dev
dependency for tests only.

## Testing

- **Unit** (`packages/*/test`, in-memory `@hozon/node-sqlite`, no Docker): port every kubun
  test (`controller-store`, `resolver-guard`, `delegation`, `remove-delegation-token`,
  `revocation-checker-fault`), with these adaptations:
  - `KubunDB` becomes `HozonDB`.
  - Tests that simulate elapsed time with a negative `graceSeconds` (for example the
    future-`iat` retention case) switch to `vi.useFakeTimers()` / `vi.setSystemTime`.
  - Tests that drive kysely's `Migrator` directly build a full hozon `MigrationContext`
    (`tablePrefix`, `kind`, `types`, `functions`) and apply `TablePrefixPlugin` to the
    Kysely instance, matching what `HozonDB` does. Otherwise they go through `HozonDB`.
- **Shared cases:** each store's API cases are written once as a parameterized suite that
  takes an adapter or `HozonDB` factory. The unit tier runs it on SQLite.
- **Integration** (new private `tests/integration` workspace, in `versioning.ignore` by
  exact name, root `test:integration` script): runs the shared suites on Postgres via
  `@testcontainers/postgresql` and `@hozon/postgres`, plus SQLite under
  `tablePrefix: 'kubun'` to pin the legacy physical names.
- **New tests:**
  - the `graceSeconds` guard (default, negative, fractional, `NaN`, both infinities, above
    `MAX_SAFE_INTEGER`), on both backends;
  - pending-purge boundaries: a row one second inside and outside
    `stored_revoked_iat + MAX_CAP_TTL_SECONDS + grace`, including a clamped future
    `revoked_iat`;
  - checker: a revocation by a rotated `did:kokuin:` issuer is still proved, a record
    signed by a denied key revokes, a record signed by a never-published key is not
    evidence, and a resolver fault rethrows;
  - `hlc` tie-breaks on node ID agree between SQL and JS, on both backends;
  - `addDelegationToken` and `addRevocation` inside an enclosing `HozonDB.withTransaction`;
  - Postgres only: concurrent `addDelegationToken` and `addRevocation` on the same key
    leave the higher-`hlc` row stored;
  - no implicit purge on insert.

## Repo setup

- Catalog: `@hozon/adapter ^0.1.0` and `@hozon/db ^0.2.0`, and `kysely ^0.29.6`. Dev
  only: `@hozon/node-sqlite ^0.1.0`, `@hozon/postgres ^0.1.0`, and
  `@testcontainers/postgresql`. Add `@hozon/*` to `minimumReleaseAgeExclude`. Cross-repo
  ranges are published `^`, never `workspace:`.
- Package scaffolding copies `packages/capability`: scripts, `tsconfig.json`,
  `tsconfig.test.json`, `publishConfig`, and license fields.
- Changesets: initial release entries for both packages, via `pnpm change`.

## Documentation

- `docs/reference/stores.md`: for both stores, cover registration, tables, the API, the
  `hlc` ordering contract, purge scheduling and its contracts, and the `tablePrefix`
  mapping to the kubun names.
- `docs/agents/architecture.md`: add the two packages and the hozon dependency edge,
  limited to them.
- `AGENTS.md` guardrails: store methods use `withStoreTransaction`, never `.transaction()`.
  No statement binds more than 500 parameters.
- Skills: add a store section to `capability.skill.md` (delegation) and `auth.skill.md`
  (controller, which that skill covers), and list both packages in `discover.skill.md`.
