import { NodeSQLiteAdapter } from '@hozon/node-sqlite'

import { vaultYieldCases } from './yield-cases.js'

vaultYieldCases({
  name: 'node:sqlite memory',
  createAdapter: async () => new NodeSQLiteAdapter({ database: ':memory:' }),
  cleanup: async () => {},
})
