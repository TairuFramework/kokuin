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
const verifyToken = createDelegationRevocationChecker(store, { methods })
```

Every write carries a caller-supplied `hlc` stamp, and the purge methods must be scheduled by the
consumer. See [docs/reference/stores.md](../../docs/reference/stores.md).
