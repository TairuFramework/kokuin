# @kokuin/store-controller

Hozon-backed store for `did:kokuin:` controller key event logs.

## Installation

```sh
npm install @kokuin/store-controller
```

## Usage

```typescript
import { HozonDB } from '@hozon/db'
import { authoritativeLog } from '@kokuin/controller'
import { controllerStoreDefinition, getControllerStore } from '@kokuin/store-controller'

const db = new HozonDB({ adapter }) // an @hozon/node-sqlite or @hozon/postgres adapter
db.register(controllerStoreDefinition)
const logs = await getControllerStore(db)

// Merge an untrusted presentation through the same arbitration the resolver uses.
// Never write peer bytes (or a `mergeLogs` union) directly: stored events of the
// current epoch are not re-verified, so a forged one would be applied.
await logs.merge(
  did,
  async (seen) => authoritativeLog({ did, loaded: presented, seen, context: 'sync' }).log,
)
const stored = await logs.get(did)
```

`getForUpdate(did)` returns the same log as `get`, holding merge's DID lock until the host transaction commits or rolls back.
It also locks an absent DID. Outside a host transaction, its own transaction releases the lock before returning.
Postgres permits concurrent merges for other DIDs. SQLite reserves its single writer, so independent writes wait regardless of DID.

Obtain the store from `db.withTransaction`'s callback provider for a read followed by a dependent write.

`markObserved(did, at = new Date()): Promise<void>` updates only the observation timestamp.
Use it after accepting an identical network presentation. It preserves the stored log bytes and returns no change signal.
Unknown DIDs are a no-op. It joins host transactions and rolls back with them.
Timestamp precision follows the adapter: SQLite stores whole seconds.
Unchanged `merge` calls still write nothing and require an explicit `markObserved` to refresh observation time.

See [docs/reference/stores.md](../../docs/reference/stores.md).
