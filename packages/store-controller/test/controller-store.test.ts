import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import { describe } from 'vitest'

import { controllerStoreCases } from './cases.js'

describe('controller store (node:sqlite memory)', () =>
  controllerStoreCases({
    name: 'memory',
    createAdapter: async () => new NodeSQLiteAdapter({ database: ':memory:' }),
    cleanup: async () => {},
  }))
