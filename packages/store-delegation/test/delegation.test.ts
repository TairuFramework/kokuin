import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import { describe } from 'vitest'

import { delegationStoreCases } from './cases.js'

describe('delegation store (node:sqlite memory)', () =>
  delegationStoreCases({
    name: 'memory',
    createAdapter: async () => new NodeSQLiteAdapter({ database: ':memory:' }),
    cleanup: async () => {},
  }))
