import { NodeSQLiteAdapter } from '@hozon/node-sqlite'

import { storeVaultCases } from './cases.js'
import { replicationCases } from './replication-cases.js'

storeVaultCases({
  name: 'node:sqlite memory',
  createAdapter: async () => new NodeSQLiteAdapter({ database: ':memory:' }),
  cleanup: async () => {},
})

replicationCases({
  name: 'node:sqlite memory',
  createAdapter: async () => new NodeSQLiteAdapter({ database: ':memory:' }),
  cleanup: async () => {},
})
