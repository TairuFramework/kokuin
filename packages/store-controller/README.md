# @kokuin/store-controller

Hozon-backed store for `did:kokuin:` controller key event logs.

## Installation

```sh
npm install @kokuin/store-controller
```

## Usage

```typescript
import { HozonDB } from '@hozon/db'
import { controllerStoreDefinition, getControllerStore } from '@kokuin/store-controller'

const db = new HozonDB({ adapter }) // an @hozon/node-sqlite or @hozon/postgres adapter
db.register(controllerStoreDefinition)
const logs = await getControllerStore(db)

await logs.set(did, log) // after the log has folded
const stored = await logs.get(did)
```

See [docs/reference/stores.md](../../docs/reference/stores.md).
