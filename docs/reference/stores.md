# Stores

Two Hozon-backed persistence packages for the identity layer. Each is a `StoreDefinition` for
[`@hozon/db`](https://github.com/TairuFramework/hozon), so it runs unchanged on `@hozon/node-sqlite`
and `@hozon/postgres`.

| Package                    | Holds                                        | API type                            |
| -------------------------- | -------------------------------------------- | ----------------------------------- |
| `@kokuin/store-controller` | `did:kokuin:` signed event logs              | `ControllerStoreAPI` (a `LogStore`) |
| `@kokuin/store-delegation` | delegation tokens and capability revocations | `DelegationStoreAPI`                |

## Registration

```typescript
import { HozonDB } from '@hozon/db'
import { controllerStoreDefinition, getControllerStore } from '@kokuin/store-controller'
import { delegationStoreDefinition, getDelegationStore } from '@kokuin/store-delegation'

const db = new HozonDB({ adapter }) // an @hozon/node-sqlite or @hozon/postgres adapter
db.register(controllerStoreDefinition)
db.register(delegationStoreDefinition)

const controllers = await getControllerStore(db)
const delegations = await getDelegationStore(db)
```

Registering runs the `0-init` migration for that store. `createControllerStore(db, adapter,
context)` takes hozon's store context, whose provider must have the controller store registered: a
merge resolves the store again on its locked transaction. `createDelegationStore(db, adapter,
context)` also requires hozon's store context, with the delegation store registered on its provider.
Both factories resolve the locked transaction's store to obtain its Kysely instance.

Store methods that read then write join a caller's enclosing transaction instead of opening a
nested one. Controller merges and delegation-token arbitration use `withKeyLock`.
Revocation upserts use `withStoreTransaction`. No statement binds more than 500 parameters.

## `@kokuin/store-controller`

### Table

`controller_logs`: one row per controller DID.

| Column       | Type      | Notes                                                                                                                                                      |
| ------------ | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `did`        | text      | primary key                                                                                                                                                |
| `log`        | json      | the accepted `ControllerLog` (`{ chain, events }`); a row written before the log split is a bare event array, read back as that chain with no epoch events |
| `created_at` | timestamp | defaults to now                                                                                                                                            |
| `updated_at` | timestamp | set on every `merge` write                                                                                                                                 |

### API

`ControllerStoreAPI` is `@kokuin/controller`'s `LogStore` plus one method:
- `get(did)`: the stored log, or `undefined`.
- `merge(did, update)`: writes what `update` makes of the stored log and returns it, the read and
  the write in one transaction, joining an enclosing one. It holds
  `withKeyLock(provider, 'controller_logs', [did])`, which serialises concurrent merges for that DID,
  also within one transaction. A consumer may hold the same lock around its own read-then-merge and
  must then obtain the store from the lock callback's provider (an outer provider waits on the lock it
  holds). The lock is re-entrant inside its callback, so merges issued there are not queued against
  each other: run them one after another. On Postgres the row is also locked on read, and a first
  insert that loses a race re-reads the winner's row and **runs `update` again** — so `update` must be
  free of side effects. On SQLite the lock reserves the writer before reading. When `update` throws, nothing is written; when it
  returns `current` itself (nothing changed, as `authoritativeLog` answers a resolution that learned
  nothing new), nothing is written either and `updated_at` does not move. A stored value that is not
  a log, or not JSON at all, reads as no memory rather than throwing. The store
  does not arbitrate: a caller ingesting an **untrusted** log (one pulled from a peer) must build the
  update from `authoritativeLog`, as the resolver does — writing peer bytes directly bypasses the
  anti-truncation guarantee.
- `getObservedAt(did)`: the time of the last explicit store write (`updated_at`, else
  `created_at`), including a locally seeded log.

Pass the store as the `history` option of `createControllerResolver` (`history: logs`) so the
resolver records each folded log and refuses one that is behind one already seen. See [security.md](./security.md).

## `@kokuin/store-delegation`

### Tables

`delegation_tokens`, primary key `(grantor, audience, resource, jti)`:

| Column                     | Type      | Notes                                                    |
| -------------------------- | --------- | -------------------------------------------------------- |
| `jti`                      | text      | indexed; not a key, see `getDelegationTokenByGrantorJTI` |
| `grantor`, `audience`      | text      | normalized with `normalizeDID` on write and read         |
| `token`                    | text      | the compact token                                        |
| `resource`, `act`          | text      |                                                          |
| `exp`                      | bigint    | unix seconds; indexed with `audience`                    |
| `hlc`                      | text      | last-writer-wins stamp, see below                        |
| `superseded`               | integer   | defaults to 0; 1 retains a losing or replaced grant       |
| `created_at`, `updated_at` | timestamp |                                                          |

`revoked_capabilities`, primary key `(jti, revoker_did)`:

| Column                     | Type             | Notes                                                             |
| -------------------------- | ---------------- | ----------------------------------------------------------------- |
| `jti`                      | text             | the revoked capability                                            |
| `revoker_did`              | text             | normalized; each author owns its own row                          |
| `revoked_iat`              | bigint           | unix seconds, floored on write (below)                            |
| `revocation_token`         | text             | the signed revocation record                                      |
| `verified_at`              | bigint, nullable | `NULL` is pending; set once a held capability confirms the issuer |
| `cap_exp`                  | bigint, nullable | set on verification; drives the expired purge                     |
| `hlc`                      | text             | last-writer-wins stamp                                            |
| `created_at`, `updated_at` | timestamp        |                                                                   |

The key is `(jti, revoker_did)` because a `jti` is chosen by whoever minted the capability and
travels to the whole group, so several members can file a claim about the same `jti`. Only the claim
signed by the capability's own issuer binds; each author can displace only its own row.

### API

Delegation tokens:
- `addDelegationToken(token)`: history-preserving last-writer-wins arbitration per `(grantor, audience, resource)`.
  A losing or equal stamp retains an unseen JTI with `superseded = 1` and returns `false`.
  A winning different JTI supersedes the active row. A winning same JTI updates its row in place.
  A partial unique index allows one active row per logical key.
  Arbitration holds `withKeyLock(context.provider, 'delegation_tokens', [grantor, audience, resource])`,
  using normalised DIDs. It serialises calls within one ambient transaction, including absent keys.
  Postgres uses an advisory transaction lock. SQLite reserves its writer before the read.
  Consumers holding this lock must obtain the store from its callback provider and issue writes sequentially.
  The callback provider inherits lock ownership, so calls made there are re-entrant.
- `getDelegationTokens({ grantor, audience })`, `listIssuedTokens(grantor)`: active rows only (`superseded = 0`).
- `getHeldTokens({ audience, atTime })`: unexpired active tokens held by `audience`, excluding any whose
  grantor has a **verified** revocation. Pending revocations do not filter.
- `listUnrevokedSupersededTokens({ grantor, audience, resource, atTime })`: unexpired superseded grants for one normalised key.
  Excludes any revocation by the grantor, pending or verified. Other revokers cannot suppress these rows.
  Orders by `hlc`, then `jti`. This lists grants still needing revocation, rather than authorising their use.
- `getDelegationTokenByGrantorJTI({ jti, grantor })`: includes superseded rows.
  Throws if that grantor holds more than one row for the `jti`, rather than pick one.
- `listDelegationTokensByJTI(jti)`: every grantor's rows, including superseded rows. Diagnostics, not authorization.
- `removeDelegationToken({ jti })`: deletes matching active and superseded rows across all grantors.

Revocations:
- `addRevocation(input)`: last-writer-wins upsert keyed by `(jti, revoker_did)`. A `revoked_iat`
  beyond `now + MAX_REVOCATION_FUTURE_DRIFT_SECONDS` (one hour) is floored to that bound, not
  rejected: the record still binds, only its retention is bounded. A row written verified
  (`verified_at` set) with `cap_exp: null` is never purged by either method below; pass `cap_exp`
  with `verified_at`, or verify through `markRevocationVerified`, which requires it.
- `getRevocationByIssuer(jti, issuer)`: the enforcement read, whatever the verification state.
- `listRevocations(jti)`: every author's claim. Diagnostics.
- `isRevokedBy(jti, issuer)`: diagnostic only, **not** an authorization read. It requires
  `verified_at IS NOT NULL`, the inverse of the enforcement rule: a co-member holds no copy of the
  capability, so its genuine revocation stays pending forever.
- `getHeldRevocations({ audience })`: verified revocations joined to locally held tokens whose
  grantor is the revoker, including superseded tokens.
- `markRevocationVerified(jti, issuer, { cap_exp, verified_at? })`,
  `getPendingRevocationByIssuer(jti, issuer)`,
  `deletePendingRevocationsFromOtherIssuers(jti, issuer)`: the cap-arrival cross-check. The
  arriving capability proves only that its own issuer's record is genuine.

The history schema is defined in `0-init`, without an additional migration.
Existing databases that recorded an older `0-init` require schema alignment before using this API.
They need the `superseded` column, four-column primary key, and partial unique active-key index.

### The `hlc` contract

Both tables store `hlc` as an opaque string. It is `NOT NULL` and required on both insert types.
The store never generates it; every caller supplies it. Last-writer-wins compares it with SQL `>`
and JS `<=`, so it must be an **ASCII** string whose **byte-wise lexicographic order matches causal
order**. ASCII because SQL compares bytes and JS compares UTF-16 code units; the two orders are only
guaranteed to agree on ASCII. A fixed-width serialized hybrid logical clock satisfies this:
`<ISO wall time>:<zero-padded counter>:<nodeID>`.
- **Local-only consumers** (no sync) may pass any strictly increasing string of that shape, for
  example `` `${new Date().toISOString()}:${String(counter).padStart(6, '0')}:${nodeID}` ``.
- **Syncing consumers** need a real hybrid logical clock serialized in that format, so stamps from
  different peers arbitrate correctly. A follow-on adds a helper and a stricter type once an HLC
  package lands in sozai.
- **Mixing** locally invented stamps with real HLC stamps in a synced store is unsupported: the local
  stamps would win or lose on wall clock alone.

SQL and JS must agree on the order. SQLite's default `BINARY` collation is byte-wise. On Postgres the
`0-init` migration creates both `hlc` columns with `COLLATE "C"`, because the default collation can be
locale-sensitive. That holds only for tables `0-init` creates. A legacy Postgres database adopted
under `tablePrefix` (see below) already records `0-init` as applied, so the migration is skipped and
its `hlc` columns keep whatever collation they were created with. Before relying on SQL/JS agreement
there, run:

```sql
ALTER TABLE <prefix>_delegation_tokens ALTER COLUMN hlc TYPE text COLLATE "C";
ALTER TABLE <prefix>_revoked_capabilities ALTER COLUMN hlc TYPE text COLLATE "C";
```

### The `boolean` from `add*`

`addDelegationToken` returns whether active content changed, comparing `jti`, `token`, `act`, and `exp`.
A new active row returns `true`. A losing stamp returns `false`, even when it inserts superseded history.
An identical re-broadcast with a newer `hlc` returns `false`. The key lock serialises arbitration and its change signal.

`addRevocation` returns whether its row changed: new rows return `true`, losing stamps return `false`.
Winning stamps return `true` only when content differs. This revocation signal remains approximate because its pre-read takes no lock.
Two concurrent revocation writers can both return `true`. Use these signals for emission gating, never authorization.

### Purging

Nothing purges implicitly. Schedule both methods yourself. Each is one time-predicate `DELETE`:
atomic, idempotent and safe alongside writes. Both take `{ graceSeconds? }`, defaulting to
`REVOCATION_GC_VERIFIED_GRACE_SECONDS` (30 days); a negative or non-integer value throws
`RangeError`.
- `purgeExpiredRevocations()` deletes verified rows whose `cap_exp` is more than the grace in the
  past. Verified rows with a null `cap_exp` are never deleted. The grace must cover the consumer's
  `clockTolerance`: a capability is still accepted up to `cap_exp + clockTolerance`, so
  `graceSeconds: 0` deletes its revocation once `cap_exp` passes and a tolerated, revoked capability
  is honoured again.
- `purgeDeadPendingRevocations()` deletes pending rows once
  `now > revoked_iat + MAX_CAP_TTL_SECONDS + grace`. The store never sees the revoked capability, so
  this is safe only while the consumer holds up its side.

Consumer contracts:
1. **Cap lifetime.** On mint **and on receive**, enforce `cap.exp - cap.iat <= MAX_CAP_TTL_SECONDS`
   (30 days), with `iat` required.
2. **Future `iat`.** On mint and on receive, enforce
   `cap.iat <= now + MAX_REVOCATION_FUTURE_DRIFT_SECONDS`. Without both, a revoked capability can
   outlive its revocation and be honoured again.
3. **Transactions and clocks.** Run a purge outside a caller transaction (on Postgres a failure
   inside one aborts it). A local clock running ahead deletes rows early; the default grace absorbs
   ordinary skew.

### Revocation checker

`createDelegationRevocationChecker(store, { methods })` is a `VerifyTokenHook` over the store, built
on `@kokuin/capability`'s `createRevocationChecker`. It throws `VerifiedRevocationError` when the
token is revoked. Pass the same resolution options (`methods`, `resolver`, `cache`) as the chain
check.

```typescript
import { checkCapability } from '@kokuin/capability'
import { createDelegationRevocationChecker } from '@kokuin/store-delegation'

const verifyToken = createDelegationRevocationChecker(delegations, { methods })
await checkCapability(permission, payload, { methods, verifyToken })
```

The returned hook also carries `.verdict(token, raw)`, resolving `true` for revoked and `false`
otherwise, for callers that prefer a value to an exception.

Behaviour worth knowing:
- **Fails closed on a dependency fault.** A store read that throws, or a resolver that throws for
  the capability's **own issuer**, makes the check throw that error rather than read as "not
  revoked". "I could not check" is not evidence of non-revocation.
- **Foreign issuers cannot deny.** A record naming another issuer cannot revoke this capability, so a
  fault resolving that issuer hides nothing and is not recorded. Counting it would let a planted
  record deny the check.
- **`IssuerKeyNotFoundError` is an answer, not a fault.** Capability's checker adjudicates it (a
  forgery is ignored; a key the log published and since denied revokes).
- **The backend never trusts a row.** `createDelegationRevocationBackend(store).get` reads by
  `(jti, issuer)`. It returns `undefined` for a record that does not decode, whose header or payload
  is not a plain object, or whose payload names a different `jti` than the one asked for.
  Capability's checker likewise treats a record whose payload is not an object, or whose `iss` is
  not a string, as no evidence.
- **A row revokes only what its signed content names.** The checker re-verifies the signature and
  revokes only when the record is signed by the capability's own issuer and its payload has
  `rev: true` and the capability's `jti`. The row's `jti` and `revoker_did` columns grant nothing: a
  genuine revocation of another `jti`, or any other token the issuer signed (a capability, say),
  filed under this `jti` is not evidence. So any row, pending or verified, can revoke at most the
  one capability its issuer signed a revocation for.
- **`loadLog` must be fresh.** For a `did:kokuin:` issuer, the method resolver's `loadLog` must
  return the issuer's current log. A genuine revocation signed with a key the local log has not seen
  yet fails with `IssuerKeyNotFoundError`, which is an answer rather than a fault, so it reads as
  "not revoked" until the log catches up.
- `add` on that backend is a no-op. Revocations enter the store through `addRevocation`, which needs
  an `hlc` and the capability cross-check this adapter does not have.

## `tablePrefix` and the legacy names

`HozonDB` takes an optional `tablePrefix`, default `hozon`. Every physical name carries it: the
logical tables become `<prefix>_controller_logs`, `<prefix>_delegation_tokens` and
`<prefix>_revoked_capabilities` (so `hozon_controller_logs` and so on by default), the migration
bookkeeping tables `<prefix>_controller_migration` and `<prefix>_delegation_migration`, and the
indexes and primary keys `<prefix>_delegation_tokens_pkey`, `<prefix>_delegation_tokens_active_key_idx`, `<prefix>_delegation_tokens_jti_idx`,
and so on.

A consumer migrating data created by an earlier in-application implementation passes that
implementation's prefix as `tablePrefix`. With it, the **table and migration-bookkeeping names
match** (`<prefix>_controller_logs`, `<prefix>_delegation_tokens`,
`<prefix>_revoked_capabilities`, same columns), but the **index and primary-key names do not**. Do not
assume a byte-identical schema; `tests/integration` pins the physical names.

Because `0-init` is already recorded in `<prefix>_delegation_migration`, it does not run against such a
database, so on Postgres the `hlc` columns do not get `COLLATE "C"`. Run the two `ALTER TABLE`
statements from [the `hlc` contract](#the-hlc-contract) with that `<prefix>` before relying on
SQL/JS agreement.

## Tests

The shared cases run against real `node:sqlite` files and a real Postgres in
`tests/integration` (`rtk proxy pnpm run test:integration`; build the store packages first, since
the tests load `lib/`). See its README.
