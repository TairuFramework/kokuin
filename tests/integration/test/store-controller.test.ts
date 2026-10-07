import { HozonDB, sql } from '@hozon/db'
import {
  createInception,
  createRotate,
  didFromInception,
  type SignedEvent,
} from '@kokuin/controller'
import { controllerStoreDefinition, getControllerStore } from '@kokuin/store-controller'
import { afterAll, describe, expect, test } from 'vitest'

import { controllerStoreCases } from '../../../packages/store-controller/test/cases.js'
import { backends, backendsNamed } from '../src/backends.js'
import { type RawDB, rawStore } from '../src/helpers.js'

describe.each(backends())('$name', (b) => {
  controllerStoreCases({
    name: b.name,
    createAdapter: () => b.createAdapter(),
    cleanup: () => b.cleanup(),
  })
})

describe.each(backendsNamed('postgres'))('$name jsonb log column', (b) => {
  afterAll(() => b.cleanup())

  // postgres.js serialises a bare JS array parameter as a Postgres array literal, so a
  // passing `get` alone would not show the column holds a JSON array.
  test('a stored log is a JSON array and round-trips', async () => {
    const seed = new Uint8Array(32).fill(7)
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate({ seed, profile: 0, did, prior: icp.event })
    const log = [icp, rot] as Array<SignedEvent>

    const db = new HozonDB({ adapter: await b.createAdapter() })
    db.register(controllerStoreDefinition)
    db.register(rawStore)
    try {
      const store = await getControllerStore(db)
      const raw = await db.getStore<RawDB>('raw')
      await store.set(did, log)
      const { rows } = await sql<{ type: string; length: number }>`
        select jsonb_typeof(log) as type, jsonb_array_length(log) as length
        from hozon_controller_logs where did = ${did}`.execute(raw)
      expect(rows).toEqual([{ type: 'array', length: 2 }])
      expect(await store.get(did)).toEqual(log)
    } finally {
      await db.close()
    }
  })
})
