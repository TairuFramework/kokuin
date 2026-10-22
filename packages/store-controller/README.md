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

See [docs/reference/stores.md](../../docs/reference/stores.md).
