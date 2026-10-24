import { NodeSQLiteAdapter } from '@hozon/node-sqlite'

import { coordinatorCases } from './coordinator-cases.js'

coordinatorCases({
  name: 'node:sqlite memory',
  createAdapter: async () => new NodeSQLiteAdapter({ database: ':memory:' }),
  cleanup: async () => {},
})
