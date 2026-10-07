# Kokuin Stores Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port kubun's controller and delegation stores into kokuin as
`@kokuin/store-controller` and `@kokuin/store-delegation` on hozon. The port removes
every kubun dependency and fixes the revocation-checker, GC and HLC-ordering issues
found in review.

**Architecture:** Each store is a hozon `StoreDefinition` (logical table names,
`ctx.tablePrefix` for index and constraint names, `withStoreTransaction` for multi-step
writes). Store API cases live in one parameterized `test/cases.ts` per package. Unit
tests run them on in-memory `node:sqlite`; a new `tests/integration` workspace runs
them on Postgres and on a file-backed SQLite database with `tablePrefix: 'kubun'`. The
revocation checker delegates all verification to `@kokuin/capability`'s
`createRevocationChecker` through an issuer-scoped backend.

**Tech Stack:** TypeScript (ESM), kysely 0.29, `@hozon/db` 0.2, `@hozon/adapter` 0.1,
`@hozon/node-sqlite`, `@hozon/postgres`, vitest, `@testcontainers/postgresql`, pnpm
workspaces, turbo, biome.

**Spec:** `docs/superpowers/specs/2026-10-07-kokuin-stores-design.md`

**Sources being ported** (read-only reference):
- `../kubun/packages/store-controller/{src,test}`
- `../kubun/packages/store-delegation/{src,test}`
- `../hozon/packages/store-blob` (hozon store idiom)
- `../hozon/tests/integration/src/{backends,global-setup}.ts` (integration harness)

## Global Constraints

- No `@kubun/*` import, dependency, comment reference (`KubunEngine`, `engine.ts:208`,
  "kubun's resolver") or brand string anywhere in the new packages. The only exceptions are
  the reference doc's `tablePrefix: 'kubun'` compatibility note and the integration
  test that pins it.
- Store methods never call `.transaction()`; multi-step writes use
  `withStoreTransaction` from `@hozon/db`.
- No statement binds more than 500 parameters.
- Cross-repo deps use published `^` ranges via the catalog (`catalog:`), never
  `workspace:`. In-repo kokuin deps use `workspace:^`.
- Store names: `controller`, `delegation`. Migration ID: `0-init` for both.
- Logical tables: `controller_logs`, `delegation_tokens`, `revoked_capabilities`.
- Constants keep their kubun values: `MAX_CAP_TTL_SECONDS = 2_592_000`,
  `REVOCATION_GC_VERIFIED_GRACE_SECONDS = 86_400 * 30`,
  `MAX_REVOCATION_FUTURE_DRIFT_SECONDS = 3_600`.
- Every DID written or compared by the delegation store goes through `normalizeDID`.
- Run scripts as `rtk proxy pnpm run <script>` (an `rtk` shim on this machine redirects
  bare `pnpm run`).
- Fake time only with `vi.useFakeTimers({ toFake: ['Date'] })`. Faking timers breaks
  the Postgres driver.

## Review Focus

1. A stored `revocation_token` that is not a decodable JWT should read as "not
   revoked", never throw out of the checker. Test in Task 5.
2. A row filed under issuer X whose `revocation_token` is signed by Y should not
   revoke X's capability. Test in Task 5.
3. `purgeExpiredRevocations()` and `purgeDeadPendingRevocations()` called with no
   argument should use the default grace and return a `number` on both backends. Test
   in Task 4.
4. `getObservedAt` should return a `Date` on Postgres (`timestamptz`) and SQLite
   (integer) after both insert and update. Test in Task 3.
5. A pending revocation with a far-future `revoked_iat` should be stored floored and
   still be purged on schedule. The kubun warn log goes, so the floor is silent and
   must be pinned by a test. Test in Task 4.

---

### Task 1: `decodeSignedToken` in `@kokuin/token`

**Files:**
- Modify: `packages/token/src/utils.ts`, `packages/token/src/index.ts:124`
- Test: `packages/token/test/decode-signed-token.test.ts`, `packages/token/test/exports.test.ts`

**Interfaces:**
- Produces: `decodeSignedToken<Payload extends Record<string, unknown> = Record<string, unknown>>(token: string): SignedToken<Payload>`.
  Parses without verifying. It throws `Error('Invalid token format: expected 3 parts separated by dots')`
  when the string has no non-empty signature part. Malformed base64 or JSON throws
  whatever `b64uToJSON` throws.

- [ ] **Step 1: Write failing tests**
  - `decodeSignedToken(stringifyToken(signed))` deep-equals `{ data, header, payload, signature }`
    of a token from `createIdentity(...).signToken({ sub: 'x' })`, where
    `data === '<h>.<p>'`.
  - It does not verify: flipping one signature character still decodes.
  - It throws for `'a.b'`, `'a.b.'`, `'not-a-token'`.
  - Add `'decodeSignedToken'` to the exports list in `exports.test.ts`.
- [ ] **Step 2:** `rtk proxy pnpm --filter @kokuin/token exec vitest run test/decode-signed-token.test.ts test/exports.test.ts`. Expect FAIL (not exported).
- [ ] **Step 3:** Implement in `utils.ts` with `b64uToJSON` from `@sozai/codec`, and export from `index.ts` beside `stringifyToken`.
- [ ] **Step 4:** Re-run. Expect PASS. Then run `rtk proxy pnpm --filter @kokuin/token run test`. Expect PASS.
- [ ] **Step 5:** Commit `feat(token): add decodeSignedToken for unverified parsing`.

### Task 2: `TokenRevokedError` and `RevocationClaims` export in `@kokuin/capability`

**Files:**
- Modify: `packages/capability/src/revocation.ts:191,198`, `packages/capability/src/index.ts:44-49`
- Test: `packages/capability/test/token-revoked-error.test.ts`

**Interfaces:**
- Produces, exported from `@kokuin/capability`:
  - `class TokenRevokedError extends Error`, `constructor(jti: string, options?: ErrorOptions)`,
    with message `` `Token revoked: ${jti}` `` and `name = 'TokenRevokedError'`. It has a static
    and an instance `brand` getter returning `'@kokuin/capability/TokenRevokedError'`, mirroring
    `UnresolvableIssuerError` in `packages/token/src/did.ts:123-152`.
  - `isTokenRevokedError(value: unknown): value is TokenRevokedError`, a brand match.
  - `type RevocationClaims`, now exported.
- `createRevocationChecker` throws `new TokenRevokedError(jti)` on the verified path
  and `new TokenRevokedError(jti, { cause: error })` on the denied-key path.

- [ ] **Step 1: Write failing tests**
  - Verified path: create a capability with `createIdentity`, revoke it with
    `createRevocationRecord` into `createMemoryRevocationBackend()`, and run
    `createRevocationChecker`. It rejects with an error where `isTokenRevokedError(e)`
    is true and `e.message === 'Token revoked: <jti>'`.
  - Denied-key path: reuse the setup of the existing denied-key revocation test in
    `packages/capability/test/` (grep `namesADeniedKey` / `Token revoked`). Assert
    `isTokenRevokedError(e)` and `e.cause` is defined.
  - `isTokenRevokedError(new Error('Token revoked: x')) === false`.
- [ ] **Step 2:** `rtk proxy pnpm --filter @kokuin/capability exec vitest run test/token-revoked-error.test.ts`. Expect FAIL.
- [ ] **Step 3:** Implement. Existing tests that match on the message text keep passing unchanged.
- [ ] **Step 4:** `rtk proxy pnpm --filter @kokuin/capability run test`. Expect PASS.
- [ ] **Step 5:** Commit `feat(capability): brand revocation refusals as TokenRevokedError`.

### Task 3: Catalog and `@kokuin/store-controller`

**Files:**
- Modify: `pnpm-workspace.yaml` (catalog, `minimumReleaseAgeExclude`)
- Create: `packages/store-controller/{package.json,tsconfig.json,tsconfig.test.json,README.md}`
- Create: `packages/store-controller/src/{tables,migrations,api,definition,index}.ts`
- Create: `packages/store-controller/test/{cases.ts,controller-store.test.ts}`

**Interfaces:**
- Catalog additions: `'@hozon/adapter': ^0.1.0`, `'@hozon/db': ^0.2.0`,
  `'@hozon/node-sqlite': ^0.1.0`, `'@hozon/postgres': ^0.1.0`,
  `'@testcontainers/postgresql': ^12.1.0`, `kysely: ^0.29.6`, `postgres: ^3.4.8`. Add
  `'@hozon/*'` to `minimumReleaseAgeExclude`.
- `package.json`: copy `packages/capability/package.json` fields (scripts, `exports`,
  `files`, `license`, `publishConfig`, `repository.directory`), with `version: 0.1.0`.
  - deps: `@hozon/adapter`, `@hozon/db`, `kysely` (catalog), `@kokuin/controller` (`workspace:^`);
  - devDeps: `@hozon/node-sqlite`, `@types/node`, `vitest` (catalog).
- `tables.ts`: `ControllerLogTable { did: string; log: ColumnType<Array<SignedEvent>, …>; created_at: CreatedAtColumn; updated_at: UpdatedAtColumn }`,
  `ControllerStoreTables = { controller_logs: ControllerLogTable }`, plus `ControllerLogRow`
  and `InsertControllerLog`. Column helper types come from `@hozon/adapter`.
- `migrations.ts`: `getControllerMigrations(ctx: MigrationContext): Record<string, Migration>`,
  returning `{ '0-init' }`, the kubun columns, and primary key `${ctx.tablePrefix}_controller_logs_pkey`
  on `did`.
- `api.ts`: `type ControllerStoreAPI = LogStore & { getObservedAt(did: string): Promise<Date | undefined> }`
  and `createControllerStore(db: Kysely<ControllerStoreTables>, adapter: Adapter): ControllerStoreAPI`,
  with kubun behaviour and comments (the untrusted-log warning on `set` stays).
- `definition.ts`: `CONTROLLER_STORE = 'controller' as const`, `controllerStoreDefinition`,
  `getControllerStore(provider: StoreProvider): Promise<ControllerStoreAPI>`.
- `index.ts` exports all of the above plus the table types.
- `test/cases.ts`:
  - `type StoreHarness = { name: string; createAdapter(): Promise<Adapter>; cleanup(): Promise<void> }`;
  - `controllerStoreCases(harness: StoreHarness, options?: { tablePrefix?: string }): void`,
    which registers vitest tests and must be called inside a `describe`.

- [ ] **Step 1: Add catalog entries, scaffold the package, `pnpm install`.** Expect the lockfile to update with no errors.
- [ ] **Step 2: Write `test/cases.ts`**
  - Move the five tests from `../kubun/packages/store-controller/test/controller-store.test.ts`
    (`registers and round-trips…`, `resolves the head signing key…`, `get returns undefined…`,
    `set is plain last-writer-wins…`, `resolve rejects an unknown DID`) and the four from
    `resolver-guard.test.ts` into `controllerStoreCases`.
  - Replace `KubunDB` with `new HozonDB({ adapter: await harness.createAdapter(), tablePrefix })`.
    `afterAll` closes the db and calls `harness.cleanup()`.
  - Add `getObservedAt returns a Date after insert and after update`: it is `undefined`
    before `set`; after the first `set` it is a `Date` within 5 s of now; after a second
    `set` it is `>=` the first.
- [ ] **Step 3: Write `controller-store.test.ts`**
  `describe('controller store (node:sqlite memory)', () => controllerStoreCases({ name: 'memory', createAdapter: async () => new NodeSQLiteAdapter({ database: ':memory:' }), cleanup: async () => {} }))`.
- [ ] **Step 4:** `rtk proxy pnpm --filter @kokuin/store-controller run test`. Expect FAIL (no src).
- [ ] **Step 5:** Implement `src/*`.
- [ ] **Step 6:** Re-run. Expect PASS for types and all 10 tests.
- [ ] **Step 7:** `grep -rn -i kubun packages/store-controller`. Expect no output.
- [ ] **Step 8:** Commit `feat(store-controller): add hozon-backed controller log store`.

### Task 4: `@kokuin/store-delegation` tables, migrations and API

**Files:**
- Create: `packages/store-delegation/{package.json,tsconfig.json,tsconfig.test.json,README.md}`
- Create: `packages/store-delegation/src/{tables,migrations,api,definition,index}.ts`
- Create: `packages/store-delegation/test/{cases.ts,delegation.test.ts}`

**Interfaces:**
- deps: `@hozon/adapter`, `@hozon/db`, `kysely` (catalog), `@kokuin/capability`,
  `@kokuin/token` (`workspace:^`). devDeps: `@hozon/node-sqlite`, `@kokuin/controller`,
  `@types/node`, `vitest`. No logger dependency.
- `tables.ts`: the kubun row types with `DelegationStoreTables = { delegation_tokens; revoked_capabilities }`.
  Doc comments on `InsertDelegationToken.hlc` and `InsertRevokedCapability.hlc` state the
  ordering contract from the spec ("HLC ordering contract"), including the local-only
  and syncing guidance.
- `migrations.ts`: `getDelegationMigrations(ctx)` → `{ '0-init' }`, with kubun columns and
  indexes (keep `.ifNotExists()`). Names:
  - `${p}_delegation_tokens_pkey` on `(grantor, audience, resource)`;
  - `${p}_delegation_tokens_grantor_audience_idx`;
  - `${p}_delegation_tokens_audience_exp_idx`;
  - `${p}_delegation_tokens_jti_idx`;
  - `${p}_revoked_capabilities_pkey` on `(jti, revoker_did)`;
  - `${p}_revoked_capabilities_verified_cap_exp_idx`.
  
  Here `p = ctx.tablePrefix`. Both `hlc` columns get `COLLATE "C"` when
  `ctx.kind === 'postgres'`, via the column builder's `modifyFront(sql\`collate "C"\`)`.
- `api.ts`: `createDelegationStore(db: Kysely<DelegationStoreTables>, adapter: Adapter): DelegationStoreAPI`.
  Changes from kubun:
  - `addDelegationToken` and `addRevocation` run pre-read and upsert in
    `withStoreTransaction(db, async (trx) => …)`. Their doc comments say the returned
    `boolean` is an approximate change signal (concurrent writers can both see `true`).
  - The sampled sweep, `REVOCATION_GC_SAMPLE_RATE`, the `logger` parameter and the
    future-`iat` warn log are removed. The floor stays.
  - `purgeExpiredRevocations(params?: { graceSeconds?: number }): Promise<number>` and
    `purgeDeadPendingRevocations(params?: { graceSeconds?: number })`:
    - grace defaults to `REVOCATION_GC_VERIFIED_GRACE_SECONDS`;
    - `Number.isSafeInteger(grace) && grace >= 0`, otherwise
      `throw new RangeError(\`graceSeconds must be a non-negative safe integer, got ${grace}\`)`;
    - one shared `nowSeconds()` (`Math.floor(Date.now() / 1000)`) feeds both cutoffs.
    
    Doc comments carry the consumer contracts from the spec ("Revocation GC").
  - Comments citing `KubunEngine`/`engine.ts`/kubun are reworded generically.
- `definition.ts`: `DELEGATION_STORE = 'delegation' as const`, `delegationStoreDefinition`,
  `getDelegationStore(provider)`.
- `test/cases.ts`:
  - `type StoreHarness = { name: string; createAdapter(): Promise<Adapter>; cleanup(): Promise<void> }`;
  - `delegationStoreCases(harness: StoreHarness, options?: { tablePrefix?: string }): void`;
  - `indexNames(db: Kysely<any>, kind: 'sqlite' | 'postgres', table: string): Promise<Array<string>>`,
    which picks the `sqlite_master` or `pg_indexes` query by `kind` and replaces the
    kubun per-harness `indexNames`.

- [ ] **Step 1: Write `test/cases.ts`**
  - Port every test in `../kubun/packages/store-delegation/test/delegation.test.ts` except
    the `createDelegationRevocationChecker (SQLite)` describe, which moves to Task 5.
    Port the three tests from `remove-delegation-token.test.ts` too.
  - Adaptations:
    - `KubunDB` becomes `HozonDB` with `tablePrefix`.
    - Physical names in raw SQL and index assertions are built from `tablePrefix ?? 'hozon'`.
    - Raw-`Migrator` cases use `migrationTableName: \`${p}_delegation_migration\``,
      `migrationLockTableName: \`${p}_delegation_migration_lock\``, a Kysely instance
      `.withPlugin(new TablePrefixPlugin(p))` for the migrations, and a full context
      `{ tablePrefix: p, kind: adapter.kind, types: adapter.types, functions: adapter.functions }`.
    - The future-`iat` retention case (kubun ~line 880-935) drops negative grace.
      It calls `vi.useFakeTimers({ toFake: ['Date'] })`, then
      `vi.setSystemTime((revoked_iat + MAX_CAP_TTL_SECONDS + REVOCATION_GC_VERIFIED_GRACE_SECONDS + 1) * 1000)`
      before purging. It restores timers in `finally`.
- [ ] **Step 2: Add new cases to `test/cases.ts`**
  - `graceSeconds guard`: `test.each([-1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1])`.
    Both purges reject with `RangeError`, and the table row count is unchanged.
  - `purges default the grace`: a verified row with
    `cap_exp = now - REVOCATION_GC_VERIFIED_GRACE_SECONDS - 1` is removed by
    `purgeExpiredRevocations()`. A row with `cap_exp = now - REVOCATION_GC_VERIFIED_GRACE_SECONDS + 60`
    stays. The return is `1` with `typeof === 'number'`. The pending purge called with
    no argument mirrors this on `revoked_iat`.
  - `pending purge boundary`: with time faked, a row at
    `revoked_iat + MAX_CAP_TTL_SECONDS + grace` survives at `now = that` and is removed at
    `now = that + 1`.
  - `future revoked_iat is floored on write`: `addRevocation` with
    `revoked_iat = now + 10 * MAX_REVOCATION_FUTURE_DRIFT_SECONDS` is stored as
    `<= now + MAX_REVOCATION_FUTURE_DRIFT_SECONDS`, and the pending purge removes it at
    `floored + MAX_CAP_TTL_SECONDS + grace + 1`.
  - `writes join an enclosing transaction`: inside
    `db.withTransaction(async (tx) => { const s = await getDelegationStore(tx); … })`,
    `addDelegationToken` and `addRevocation` resolve. A throw afterwards rolls both back, so the reads after return nothing.
  - `no implicit purge on insert`: insert an expired verified row, run 300 `addDelegationToken`
    calls with distinct resources, and the expired row is still present.
  - `hlc tie-break agrees between SQL and JS`: two stamps
    `'2026-01-01T00:00:00.000Z:000000000001:' + id` with ids `'B'` vs `'a'` and `'node-9'` vs `'node-10'`.
    Insert the lower stamp then the higher (by JS `<`), and the stored row carries the
    higher. Insert the reverse order on a fresh key: the stored row still carries the
    higher, and `addDelegationToken` returns `false` for the loser.
- [ ] **Step 3: Write `delegation.test.ts`**, which calls `delegationStoreCases` on an in-memory `NodeSQLiteAdapter`, as in Task 3.
- [ ] **Step 4:** `rtk proxy pnpm --filter @kokuin/store-delegation run test`. Expect FAIL.
- [ ] **Step 5:** Implement `src/{tables,migrations,api,definition,index}.ts`.
- [ ] **Step 6:** Re-run. Expect PASS.
- [ ] **Step 7:** Audit bound parameters: every statement in `api.ts` binds a fixed, small count (no `IN` lists built from input, no multi-row values). Record this in a one-line comment at the top of `api.ts`.
- [ ] **Step 8:** Commit `feat(store-delegation): add hozon-backed delegation store`.

### Task 5: Delegation revocation backend and checker

**Files:**
- Create: `packages/store-delegation/src/revocation-checker.ts`
- Modify: `packages/store-delegation/src/index.ts`
- Test: `packages/store-delegation/test/revocation-checker.test.ts`

**Interfaces:**
- Consumes: `decodeSignedToken` (Task 1); `TokenRevokedError`, `isTokenRevokedError`,
  `RevocationClaims` and `RevocationOptions` (Task 2); `DelegationStoreAPI.getRevocationByIssuer` (Task 4).
- Produces:
  - `createDelegationRevocationBackend(api: DelegationStoreAPI): RevocationBackend`:
    - `get(jti, issuer)` reads `api.getRevocationByIssuer(jti, issuer)` and returns
      `decodeSignedToken<RevocationClaims>(row.revocation_token)`;
    - it returns `undefined` when there is no row or decode throws;
    - store errors propagate;
    - `add` is a no-op with the kubun comment.
  - `createDelegationRevocationChecker(api: DelegationStoreAPI, options?: RevocationOptions): VerifyTokenHook & { verdict(token, raw): Promise<boolean> }`.
  - `class VerifiedRevocationError extends Error` with brand
    `'@kokuin/store-delegation/VerifiedRevocationError'`.
  - Re-export `type RevocationClaims` from `@kokuin/capability`.
- `verdict` algorithm:
  1. Wrap each `options.methods` resolver function (`resolve`, `resolveHistoric`,
     `resolveDenySet`, `resolveAgreementKey`, when present) and the backend's `get`, so
     the first thrown error is recorded and rethrown. Keep kubun's `wrap` and
     `recordFault` shape.
  2. Call `await createRevocationChecker(trackedBackend, { ...options, methods: trackedMethods })(token, raw)`.
  3. If a fault was recorded, rethrow it on either outcome, before inspecting the result.
  4. Map a thrown `isTokenRevokedError` to `true` and a normal return to `false`. Rethrow
     anything else.
  
  The hook throws `new VerifiedRevocationError(\`Token revoked: ${jti}\`)` when `verdict` is `true`.

- [ ] **Step 1: Write `test/revocation-checker.test.ts`**
  - Port the `createDelegationRevocationChecker (SQLite)` describe from kubun
    `delegation.test.ts:1078` and both cases from `revocation-checker-fault.test.ts`.
    The second argument changes from `[resolver]` to `{ methods: [resolver] }`.
  - Add these cases, using `@kokuin/controller` (`createInception`, `createRotate`,
    `createControllerIdentity`, `createControllerResolver`) as in kubun's fault test:
    - `rotated issuer`: revoke under generation 0, rotate, and check with a resolver
      serving the rotated log. Rejects `VerifiedRevocationError`.
    - `denied key`: revocation signed by a key later denied (mirror Task 2's denied-key
      setup). Rejects `VerifiedRevocationError`.
    - `never-published key`: record signed by an unrelated `createIdentity` but stored
      under the issuer's DID. `verdict` resolves `false`.
    - `corrupt stored record` (Review Focus 1): `revocation_token: 'garbage'`. `verdict`
      resolves `false`.
    - `record signed by another issuer` (Review Focus 2): a row with
      `revoker_did = X` holds Y's record. `verdict` resolves `false`.
    - `backend scopes by issuer`: rows for the same `jti` from issuer A and co-member B.
      `createDelegationRevocationBackend(store).get(jti, normalizeDID(A))` returns A's
      record, and `get(jti, 'did:key:unknown')` returns `undefined`.
- [ ] **Step 2:** `rtk proxy pnpm --filter @kokuin/store-delegation exec vitest run test/revocation-checker.test.ts`. Expect FAIL.
- [ ] **Step 3:** Implement `revocation-checker.ts` and the exports.
- [ ] **Step 4:** `rtk proxy pnpm --filter @kokuin/store-delegation run test`. Expect PASS.
- [ ] **Step 5:** `grep -rn -i kubun packages/store-delegation`. Expect no output.
- [ ] **Step 6:** Commit `feat(store-delegation): verify revocations through capability's checker`.

### Task 6: Integration workspace (Postgres and legacy names)

**Files:**
- Create: `tests/integration/{package.json,tsconfig.json,vitest.config.ts,docker-compose.yml,README.md}`
- Create: `tests/integration/src/{backends.ts,global-setup.ts}`
- Create: `tests/integration/test/{store-controller,store-delegation,legacy-names,concurrency}.test.ts`
- Modify: root `package.json` (add `"test:integration": "pnpm run --filter integration-tests test"`),
  `pnpm-workspace.yaml` (`versioning.ignore` += `integration-tests`)

**Interfaces:**
- `backends.ts` and `global-setup.ts` are copied from `../hozon/tests/integration/src/`,
  with env vars renamed to `KOKUIN_INTEGRATION_BACKENDS` and `KOKUIN_POSTGRES_URL`.
  `backends(): Array<Backend>` keeps the same shape.
- Package `integration-tests`, private, `version: 0.0.0`.
  - deps: `@hozon/adapter`, `@hozon/db`, `@hozon/node-sqlite`, `@hozon/postgres`,
    `kysely`, `postgres` (catalog), `@kokuin/{capability,controller,token,store-controller,store-delegation}` (`workspace:^`);
  - devDeps: `@testcontainers/postgresql`, `@types/node`, `vitest`.
- Test files import the case builders by relative path:
  `../../../packages/store-delegation/test/cases.js`.

- [ ] **Step 1: Write tests**
  - `store-controller.test.ts` and `store-delegation.test.ts`:
    `describe.each(backends())('$name', (b) => xStoreCases({ name: b.name, createAdapter: () => b.createAdapter(), cleanup: () => b.cleanup() }))`.
  - `legacy-names.test.ts`: for each backend, open `HozonDB({ tablePrefix: 'kubun' })`
    with both stores and assert via catalog queries:
    - tables `kubun_controller_logs`, `kubun_delegation_tokens` and `kubun_revoked_capabilities`;
    - migration tables `kubun_controller_migration` and `kubun_delegation_migration`;
    - the Task 4 index names with the `kubun_` prefix;
    - on Postgres only, `hlc` columns with `collation_name = 'C'` in `information_schema.columns`.
  - `concurrency.test.ts`, Postgres only (skip otherwise): two `HozonDB` instances on
    one database. `Promise.all` of `addDelegationToken` with `hlc(1)` and `hlc(2)` on the
    same key, repeated 20 times on fresh keys. The stored `hlc` is always `hlc(2)`. Same
    for `addRevocation`.
- [ ] **Step 2:** `rtk proxy pnpm run test:integration` with Docker running. Expect PASS on `node-sqlite` and `postgres`. `KOKUIN_INTEGRATION_BACKENDS=node-sqlite` must pass without Docker.
- [ ] **Step 3:** Fix any backend-specific failures in the store packages (not in the cases). Re-run until green.
- [ ] **Step 4:** Commit `test(integration): run store cases on Postgres and pin legacy names`.

### Task 7: Docs, skills and release intents

**Files:**
- Create: `docs/reference/stores.md`, `packages/store-*/README.md` (install snippet like `packages/capability/README.md`)
- Modify: `docs/agents/architecture.md`, `AGENTS.md` (Guardrails), `docs/skills/capability.skill.md`, `docs/skills/auth.skill.md`, `docs/skills/discover.skill.md`, `docs/index.md` (link)

- [ ] **Step 1: Write `docs/reference/stores.md`.** For both stores, cover:
  - registration (`db.register(...)`, `getXStore(db)`);
  - tables and columns;
  - the API;
  - the `hlc` contract (local-only vs syncing, `@kubun/hlc` today, mixing unsupported);
  - purge scheduling and the three consumer contracts;
  - the approximate `boolean` from the add methods;
  - checker usage (`createDelegationRevocationChecker(store, { methods })` as a `verifyToken` hook);
  - the `tablePrefix: 'kubun'` note (data tables match, index and constraint names differ).
- [ ] **Step 2: Update `architecture.md`** (packages list, and the hozon dependency edge limited to the two store packages) and add the two guardrails to `AGENTS.md`. Add store sections to the skills and list both packages in `discover.skill.md`.
- [ ] **Step 3: Create release intents** per the `kigu:releasing` skill (`pnpm change`):
  - minor for `@kokuin/token` (`decodeSignedToken`);
  - minor for `@kokuin/capability` (`TokenRevokedError`, `RevocationClaims` export);
  - initial `0.1.0` for both store packages.
- [ ] **Step 4:** Run `rtk proxy pnpm run build`, `rtk proxy pnpm run test` and `pnpm exec biome check ./packages ./tests`. Expect all PASS.
- [ ] **Step 5:** Commit `docs: document kokuin stores`.
