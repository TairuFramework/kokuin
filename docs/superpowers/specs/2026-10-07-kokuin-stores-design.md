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
  move as is. The error brand becomes `@kokuin/store-delegation/VerifiedRevocationError`.
- Every DID crossing the store boundary is still folded through `normalizeDID`.

## Changes from the kubun originals

### Kubun removal

- `@kubun/db` becomes `@hozon/db`; `@kubun/db-adapter` becomes `@hozon/adapter`
  (`Adapter`, `CreatedAtColumn`, `UpdatedAtColumn`).
- `kubun_*` physical table names become logical names. Under
  `HozonDB({ tablePrefix: 'kubun' })` they resolve to the kubun names
  (`kubun_controller_logs`, `kubun_delegation_tokens`, `kubun_revoked_capabilities`).
- Constraint and index names use `${ctx.tablePrefix}_…`, following `@hozon/store-blob`.
  For example, `pk_delegation_tokens` becomes `${ctx.tablePrefix}_delegation_tokens_pkey`.
- Comments that cite kubun internals (`KubunEngine`, `engine.ts:208`, "kubun's resolver")
  are reworded in generic consumer terms. They keep the rationale.

### Transactions

- `addDelegationToken` and `addRevocation` run their pre-read and upsert inside
  `withStoreTransaction`. It reuses an enclosing transaction, so the kubun reason for
  leaving them unwrapped (nested transactions) no longer applies. The read/upsert race
  noted in kubun is gone.
- No store method calls `.transaction()` directly.
- No statement binds more than 500 parameters. Every current statement binds a fixed,
  small number of parameters; the plan audits each one.

### Revocation GC

The kubun `addDelegationToken` ran a sampled purge (1%) and caught its errors. On
Postgres a failed statement aborts the enclosing transaction, so catching in JS did not
protect the caller, and the store's `Kysely` handle cannot open savepoints. The sampled
sweep is removed, along with `REVOCATION_GC_SAMPLE_RATE` and the logger.

Consumers call `purgeExpiredRevocations` and `purgeDeadPendingRevocations` on their own
schedule. Both are single time-predicate `DELETE`s: atomic, idempotent, and safe to run at
any time and concurrently with writes. Calling them rarely only grows the table.

Guard: `graceSeconds` becomes optional (`{ graceSeconds?: number }`) and defaults to
`REVOCATION_GC_VERIFIED_GRACE_SECONDS`. A negative or non-finite value throws
`RangeError`. A negative grace would delete revocations of still-valid capabilities,
which un-revokes them.

Documented consumer contracts:

- The pending purge is safe only if every accepted capability satisfies
  `exp - iat ≤ MAX_CAP_TTL_SECONDS`. The store never sees the capability, so the
  consumer enforces this on mint and on receive.
- Run purges outside a caller transaction. On Postgres a failure inside one aborts it.
- A local clock running ahead deletes rows early. The default grace absorbs ordinary skew.

### HLC ordering contract

No code depends on an HLC package. Both tables store `hlc` as an opaque string.
Last-writer-wins compares it with SQL `>` and JS `<=`. The column contract, documented on
the insert types and in the reference: `hlc` must be a string whose lexicographic order
matches causal order. A fixed-width serialized HLC satisfies this. Tests use literal
fixed-width strings. When the HLC package lands in sozai, it may become a dev dependency
for tests only.

## Testing

- **Unit** (`packages/*/test`, in-memory `@hozon/node-sqlite`, no Docker): port every kubun
  test, swapping `KubunDB` for `HozonDB`. That covers `controller-store`,
  `resolver-guard`, `delegation`, `remove-delegation-token`, and
  `revocation-checker-fault`.
- **Shared cases:** each store's API cases are written once as a parameterized suite that
  takes an adapter or `HozonDB` factory. The unit tier runs it on SQLite.
- **Integration** (new private `tests/integration` workspace, in `versioning.ignore` by
  exact name, root `test:integration` script): runs the shared suites on Postgres via
  `@testcontainers/postgresql` and `@hozon/postgres`, plus SQLite under
  `tablePrefix: 'kubun'` to pin the legacy physical names.
- **New tests:**
  - the `graceSeconds` guard (default, negative, `NaN`);
  - `addDelegationToken` and `addRevocation` inside an enclosing `HozonDB.withTransaction`;
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
