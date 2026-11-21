import { HozonDB } from '@hozon/db'
import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import { randomIdentity } from '@kokuin/token'
import { VAULT_OP_KIND } from '@kokuin/vault'
import type * as SozaiAsync from '@sozai/async'
import { createRuntime } from '@sozai/runtime'
import { beforeEach, expect, test, vi } from 'vitest'

import { clearRecordOpMemo } from '../../records/src/op.js'
import { clearVerifiedSignatureMemo } from '../../token/src/verified-memo.js'
import {
  createVaultCoordinator,
  getVaultRecordsStore,
  getVaultStore,
  vaultRecordsStoreDefinition,
  vaultStoreDefinition,
} from '../src/index.js'

const timers = vi.hoisted(() =>
  vi.fn((callback: () => void) => {
    setTimeout(callback, 0)
  }),
)
vi.mock('@sozai/async', async (importOriginal) => {
  const original = await importOriginal<typeof SozaiAsync>()
  return {
    ...original,
    maybeYield: original.createYielder({ budgetMs: 0, schedule: timers }).maybeYield,
  }
})
function clearMemos() {
  clearVerifiedSignatureMemo()
  clearRecordOpMemo()
  timers.mockClear()
}
beforeEach(clearMemos)

for (const policy of [
  { yield: false },
  {},
  { recordsYield: false },
  { yield: false, recordsYield: true },
  { yield: true, recordsYield: false },
]) {
  test(`replicated coordinator forwards yield ${policy.yield} with records policy ${policy.recordsYield} through signing, apply and stored reads`, async () => {
    const db = new HozonDB({ adapter: new NodeSQLiteAdapter({ database: ':memory:' }) })
    try {
      db.register(vaultStoreDefinition)
      db.register(vaultRecordsStoreDefinition)
      await getVaultRecordsStore({ provider: db, opKind: VAULT_OP_KIND })
      const identity = randomIdentity()
      let counter = 0
      const coordinator = createVaultCoordinator({
        ...policy,
        mode: 'replicated',
        identity,
        signer: identity,
        principal: identity.id,
        store: await getVaultStore(db),
        runtime: createRuntime(),
        authority: { authorize: async () => true },
        nextHLC: async () => `2026-10-01T00:00:00.000Z:${String(++counter).padStart(8, '0')}:yield`,
        records: {
          opKind: VAULT_OP_KIND,
          yield: policy.recordsYield,
          nowMS: () => Date.parse('2026-10-01T01:00:00Z'),
          maxDriftMS: 60000,
          validateConsumerMetadata: async () => true,
        },
      })
      clearMemos()
      const key = await coordinator.createKey({ ownerDID: identity.id })
      expect(timers.mock.calls.length > 0).toBe((policy.yield ?? policy.recordsYield) !== false)
      clearMemos()
      const entry = await coordinator.putEntry({
        ...key,
        entryID: 'entry',
        kind: 'blob',
        label: 'Secret',
        attributes: {},
        plaintext: new Uint8Array([1, 2, 3]),
      })
      expect(timers.mock.calls.length > 0).toBe((policy.yield ?? policy.recordsYield) !== false)
      clearMemos()
      expect(await coordinator.readEntry(entry)).toEqual(new Uint8Array([1, 2, 3]))
      expect(timers.mock.calls.length > 0).toBe((policy.yield ?? policy.recordsYield) !== false)
      clearMemos()
      expect(
        await coordinator.records.adapter.get({
          type: 'vault.key',
          owner: key.ownerDID,
          id: key.keyID,
        }),
      ).toMatchObject({ key: { id: key.keyID } })
      expect(timers.mock.calls.length > 0).toBe((policy.yield ?? policy.recordsYield) !== false)
    } finally {
      await db.close()
    }
  })
}
