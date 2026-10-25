import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import { describe } from 'vitest'

import { controllerStoreCases } from './cases.js'

describe('controller store (node:sqlite file)', () => {
  let directory: string
  const open = () => {
    return new NodeSQLiteAdapter({
      database: join(directory, 'controller.db'),
      pragmas: { busyTimeout: 0 },
    })
  }
  controllerStoreCases({
    name: 'file',
    createAdapter: async () => {
      directory = await mkdtemp(join(tmpdir(), 'kokuin-controller-'))
      return open()
    },
    reopen: async () => open(),
    cleanup: async () => {
      await rm(directory, { recursive: true, force: true })
    },
  })
})
