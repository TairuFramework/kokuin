# @kokuin/store-delegation

Hozon-backed store for delegation tokens and capability revocations.

## Installation

```sh
npm install @kokuin/store-delegation
```

## Usage

```typescript
import { HozonDB } from '@hozon/db'
import {
  createDelegationRevocationChecker,
  delegationStoreDefinition,
  getDelegationStore,
} from '@kokuin/store-delegation'

const db = new HozonDB({ adapter }) // an @hozon/node-sqlite or @hozon/postgres adapter
db.register(delegationStoreDefinition)
const store = await getDelegationStore(db)

// A `verifyToken` hook for `@kokuin/capability`'s `checkCapability`.
const verifyToken = createDelegationRevocationChecker({ api: store, methods })
```

The checker and its `verdict` accept per-call `yield?: boolean`, forwarded by `checkCapability`.
A supplied policy overrides the construction policy. Omitting it retains the captured policy and default yielding.

Every write carries a caller-supplied `hlc` stamp, and the purge methods must be scheduled by the
consumer. See [docs/reference/stores.md](../../docs/reference/stores.md).

## Crypto provider migration to 0.7.0

`createDelegationRevocationChecker(params: CreateDelegationRevocationCheckerParams)` accepts `options.crypto?: CryptoProvider`.
It captures options and forwards the provider through tracked backend and resolver wrappers.
`createDelegationRevocationBackend` retains its signature. Checker construction stays synchronous and its returned hook stays asynchronous.
Strict default verification applies on reverification. Custom algorithm verifiers retain precedence and own their policy.
Provider operational failures propagate unchanged. No historical rescan or version gate is introduced.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new VerifiedRevocationError` | `VerifiedRevocationErrorParams` | `message, options?` |

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.

Additional APIs use the same flat params convention.

| Export | Named params type | Previous positional form |
| --- | --- | --- |
| `createDelegationStore` | `CreateDelegationStoreParams` | `createDelegationStore(db: Kysely<DelegationStoreTables>, adapter: Adapter, context: StoreContext)` |
| `createDelegationRevocationChecker` | `CreateDelegationRevocationCheckerParams` | `createDelegationRevocationChecker(params: CreateDelegationRevocationCheckerParams)` |

Method and callback contracts follow the same convention.

| API | Named params type | Previous form |
| --- | --- | --- |
| `DelegationStoreAPI.getRevocationByIssuer` | `DelegationStoreAPIGetRevocationByIssuerParams` | `getRevocationByIssuer(jti, issuer)` |
| `DelegationStoreAPI.isRevokedBy` | `DelegationStoreAPIIsRevokedByParams` | `isRevokedBy(jti, issuer)` |
| `DelegationStoreAPI.markRevocationVerified` | `DelegationStoreAPIMarkRevocationVerifiedParams` | `markRevocationVerified(jti, issuer, params)` |
| `DelegationStoreAPI.getPendingRevocationByIssuer` | `DelegationStoreAPIGetPendingRevocationByIssuerParams` | `getPendingRevocationByIssuer(jti, issuer)` |
| `DelegationStoreAPI.deletePendingRevocationsFromOtherIssuers` | `DelegationStoreAPIDeletePendingRevocationsFromOtherIssuersParams` | `deletePendingRevocationsFromOtherIssuers(jti, issuer)` |

| API | Named params type | Previous form |
| --- | --- | --- |
| `createDelegationRevocationChecker(...).verdict` | `DelegationRevocationVerdictParams` | `verdict(token, raw)` |

## Bounded held-token reads

`getHeldTokenStats({ audience, atTime })` returns `{ count, bytes }` using SQL aggregates without fetching token rows.
`getHeldTokenPage({ audience, atTime, after?, limit, maxBytes? })` returns `{ tokens, next, oversized? }` with the same authority filters as `getHeldTokens`.
The package exports `HeldTokenStats`, `HeldTokenPage`, `HeldTokenPageOversized` and `MAX_HELD_TOKEN_PAGE_SIZE` (1,000).
Limits outside the integer range 1–1,000 throw `RangeError`.

Pass `next` as `after` until it is `null`, keeping the audience and time fixed.
Pages use the composite table key, since JTIs are not globally unique.
Stats count UTF-8 token bytes on PostgreSQL and adapter-created SQLite databases.
See the [store reference](../../docs/reference/stores.md) for encoding, cursor and concurrency contracts.
Without `maxBytes`, pages retain their row-only bound.
Optional `maxBytes` must be a positive safe integer, otherwise the call throws `RangeError`.
SQL returns the longest key-ordered prefix within both limits, measuring token bytes with the stats expression.
Bodies outside that prefix never reach the driver result, including after concurrent inserts or replacements.
If the first eligible row exceeds the allowance, the page returns no tokens and `oversized: { jti, bytes }`.
On that result, `next` equals the requested `after`, or `null` when `after` was omitted.
Check `oversized` before treating `next: null` as completion. Retry with a larger allowance or stop.
The byte allowance covers token bodies only, excluding row metadata and driver overhead.
Use a caller transaction with snapshot isolation for a consistent preflight and page traversal.
