# Stores

Two Hozon-backed persistence packages for the identity layer. Each is a `StoreDefinition` for
[`@hozon/db`](https://github.com/TairuFramework/hozon), so it runs unchanged on `@hozon/node-sqlite`
and `@hozon/postgres`.

| Package | Holds | API type |
|---------|-------|----------|
| `@kokuin/store-controller` | `did:kokuin:` signed event logs | `ControllerStoreAPI` (a `LogStore`) |
| `@kokuin/store-delegation` | delegation tokens and capability revocations | `DelegationStoreAPI` |

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

Registering runs the `0-init` migration for that store. `createControllerStore(db, adapter)` and
`createDelegationStore(db, adapter)` build the API over a Kysely instance directly, for a caller that
manages its own migrations.

Store methods that read then write use `withStoreTransaction`, which joins a caller's enclosing
transaction instead of opening a nested one. No statement binds more than 500 parameters.

## `@kokuin/store-controller`

### Table

`controller_logs`: one row per controller DID.

| Column | Type | Notes |
|--------|------|-------|
| `did` | text | primary key |
| `log` | json | the signed event array, verbatim |
| `created_at` | timestamp | defaults to now |
| `updated_at` | timestamp | set on every `set` |

### API

`ControllerStoreAPI` is `@kokuin/controller`'s `LogStore` plus one method:

- `get(did)`: the stored log, or `undefined`.
- `set(did, log)`: plain last-writer-wins upsert. The store does not arbitrate. Arbitration lives
  in the resolver, which calls `set` only after the log has folded. A caller ingesting an
  **untrusted** log (one pulled from a peer) must run it through the resolver's
  `authoritativeStates` / `history` guard first: a direct `set` of peer bytes bypasses the
  anti-truncation guarantee.
- `getObservedAt(did)`: the time of the last explicit store write (`updated_at`, else
  `created_at`), including a locally seeded log.

Pass the store as the `history` option of `createControllerResolver` (`history: logs`) so the
resolver records each folded log and refuses one that is behind one already seen. See [security.md](./security.md).

## `@kokuin/store-delegation`

### Tables

`delegation_tokens`, primary key `(grantor, audience, resource)`:

| Column | Type | Notes |
|--------|------|-------|
| `jti` | text | indexed; not a key, see `getDelegationTokenByGrantorJTI` |
| `grantor`, `audience` | text | normalized with `normalizeDID` on write and read |
| `token` | text | the compact token |
| `resource`, `act` | text | |
| `exp` | bigint | unix seconds; indexed with `audience` |
| `hlc` | text | last-writer-wins stamp, see below |
| `created_at`, `updated_at` | timestamp | |

`revoked_capabilities`, primary key `(jti, revoker_did)`:

| Column | Type | Notes |
|--------|------|-------|
| `jti` | text | the revoked capability |
| `revoker_did` | text | normalized; each author owns its own row |
| `revoked_iat` | bigint | unix seconds, floored on write (below) |
| `revocation_token` | text | the signed revocation record |
| `verified_at` | bigint, nullable | `NULL` is pending; set once a held capability confirms the issuer |
| `cap_exp` | bigint, nullable | set on verification; drives the expired purge |
| `hlc` | text | last-writer-wins stamp |
| `created_at`, `updated_at` | timestamp | |

The key is `(jti, revoker_did)` because a `jti` is chosen by whoever minted the capability and
travels to the whole group, so several members can file a claim about the same `jti`. Only the claim
signed by the capability's own issuer binds; each author can displace only its own row.

### API

Delegation tokens:

- `addDelegationToken(token)`: last-writer-wins upsert keyed by `(grantor, audience, resource)`.
- `getDelegationTokens({ grantor, audience })`, `listIssuedTokens(grantor)`.
- `getHeldTokens({ audience, atTime })`: unexpired tokens held by `audience`, excluding any whose
  grantor has a **verified** revocation. Pending revocations do not filter.
- `getDelegationTokenByGrantorJTI({ jti, grantor })`: throws if that grantor holds more than one
  row for the `jti`, rather than pick one.
- `listDelegationTokensByJTI(jti)`: every grantor's row. Diagnostics, not authorization.
- `removeDelegationToken({ jti })`.

Revocations:

- `addRevocation(input)`: last-writer-wins upsert keyed by `(jti, revoker_did)`. A `revoked_iat`
  beyond `now + MAX_REVOCATION_FUTURE_DRIFT_SECONDS` (one hour) is floored to that bound, not
  rejected: the record still binds, only its retention is bounded.
- `getRevocationByIssuer(jti, issuer)`: the enforcement read, whatever the verification state.
- `listRevocations(jti)`: every author's claim. Diagnostics.
- `isRevokedBy(jti, issuer)`: diagnostic only, **not** an authorization read. It requires
  `verified_at IS NOT NULL`, the inverse of the enforcement rule: a co-member holds no copy of the
  capability, so its genuine revocation stays pending forever.
- `getHeldRevocations({ audience })`: verified revocations joined to locally held tokens whose
  grantor is the revoker.
- `markRevocationVerified(jti, issuer, { cap_exp, verified_at? })`,
  `getPendingRevocationByIssuer(jti, issuer)`,
  `deletePendingRevocationsFromOtherIssuers(jti, issuer)`: the cap-arrival cross-check. The
  arriving capability proves only that its own issuer's record is genuine.

### The `hlc` contract

Both tables store `hlc` as an opaque string. It is `NOT NULL` and required on both insert types.
The store never generates it; every caller supplies it. Last-writer-wins compares it with SQL `>`
and JS `<=`, so it must be a string whose **byte-wise lexicographic order matches causal order**. A
fixed-width serialized hybrid logical clock satisfies this:
`<ISO wall time>:<zero-padded counter>:<nodeID>`.

- **Local-only consumers** (no sync) may pass any strictly increasing string of that shape, for
  example `` `${new Date().toISOString()}:${String(counter).padStart(6, '0')}:${nodeID}` ``.
- **Syncing consumers** need a real hybrid logical clock serialized in that format, so stamps from
  different peers arbitrate correctly. Today that is
  [`@kubun/hlc`](https://github.com/TairuFramework/kubun). A follow-on adds a helper and a stricter
  type once the HLC package moves to sozai.
- **Mixing** locally invented stamps with real HLC stamps in a synced store is unsupported: the local
  stamps would win or lose on wall clock alone.

SQL and JS must agree on the order. SQLite's default `BINARY` collation is byte-wise. On Postgres the
migration adds `COLLATE "C"` to both `hlc` columns, because the default collation can be
locale-sensitive.

### The `boolean` from `add*`

`addDelegationToken` and `addRevocation` return whether the stored row changed: `true` for a new
row, `false` when the stamp loses, and `true` only if content differs when it wins (an identical
re-broadcast with a newer `hlc` is `false`). Treat it as an **approximate** change signal for
gating emission. The pre-read takes no lock, so two concurrent writers can both see `true`. Never
use it for correctness.

### Purging

Nothing purges implicitly. Schedule both methods yourself. Each is one time-predicate `DELETE`:
atomic, idempotent and safe alongside writes. Both take `{ graceSeconds? }`, defaulting to
`REVOCATION_GC_VERIFIED_GRACE_SECONDS` (30 days); a negative or non-integer value throws
`RangeError`.

- `purgeExpiredRevocations()` deletes verified rows whose `cap_exp` is more than the grace in the
  past.
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
  `(jti, issuer)`. It returns `undefined` for a record that does not decode, or whose header or
  payload is not a plain object. Capability's checker likewise treats a record whose payload is not
  an object, or whose `iss` is not a string, as no evidence. The checker re-verifies the signature,
  so a pending row is safe to hand over.
- `add` on that backend is a no-op. Revocations enter the store through `addRevocation`, which needs
  an `hlc` and the capability cross-check this adapter does not have.

## `tablePrefix` and the legacy names

`HozonDB` takes an optional `tablePrefix`. The prefix names primary keys and indexes
(`<prefix>_delegation_tokens_pkey`, ...); table names are fixed. A consumer migrating data created
by the earlier in-application implementation passes `tablePrefix: 'kubun'`. With it, the **data
tables match** (`controller_logs`, `delegation_tokens`, `revoked_capabilities`, same columns), but the
**index and constraint names differ** from that implementation's. Do not assume a byte-identical
schema; `tests/integration` pins the physical names.

## Tests

The shared cases run against real `node:sqlite` files and a real Postgres in
`tests/integration` (`rtk proxy pnpm run test:integration`; build the store packages first, since
the tests load `lib/`). See its README.
