import { HozonDB, type StoreProvider } from '@hozon/db'
import { signRecordOp, verifySignedRecord } from '@kokuin/records'
import { randomIdentity } from '@kokuin/token'
import { VAULT_OP_KIND } from '@kokuin/vault'
import type * as SozaiAsync from '@sozai/async'
import { createRuntime } from '@sozai/runtime'
import { beforeEach, expect, test, vi } from 'vitest'

import { clearRecordOpMemo } from '../../records/lib/op.js'
import { clearVerifiedSignatureMemo } from '../../token/lib/verified-memo.js'
import {
  createVaultCoordinator,
  getVaultRecordsStore,
  getVaultStore,
  VaultWriteConflict,
  vaultRecordsStoreDefinition,
  vaultStoreDefinition,
} from '../src/index.js'

const writer = vi.hoisted(() => ({ connections: new Set<object>(), timers: 0 }))
const timers = vi.hoisted(() =>
  vi.fn((callback: () => void) => {
    if (writer.connections.size > 0) writer.timers += 1
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
  writer.timers = 0
}
beforeEach(clearMemos)

import type { StoreHarness } from './cases.js'

export function vaultYieldCases(harness: StoreHarness): void {
  for (const ambient of [false, true]) {
    for (const policy of [
      { yield: false },
      {},
      { yield: true },
      { recordsYield: false },
      { yield: false, recordsYield: true },
      { yield: true, recordsYield: false },
    ]) {
      test(`${harness.name}: ambient=${ambient}: replicated coordinator forwards yield ${policy.yield} with records policy ${policy.recordsYield} through signing, apply and stored reads`, async () => {
        const adapter = await harness.createAdapter()
        const createDriver = adapter.dialect.createDriver.bind(adapter.dialect)
        const driverSpy = vi.spyOn(adapter.dialect, 'createDriver').mockImplementation(() => {
          const driver = createDriver()
          const begin = driver.beginTransaction.bind(driver)
          const release = driver.releaseConnection.bind(driver)
          vi.spyOn(driver, 'beginTransaction').mockImplementation(async (...args) => {
            writer.connections.add(args[0])
            return begin(...args)
          })
          vi.spyOn(driver, 'releaseConnection').mockImplementation(async (...args) => {
            try {
              return await release(...args)
            } finally {
              writer.connections.delete(args[0])
            }
          })
          return driver
        })
        const db = new HozonDB({ adapter })
        try {
          db.register(vaultStoreDefinition)
          db.register(vaultRecordsStoreDefinition)
          await getVaultRecordsStore({ provider: db, opKind: VAULT_OP_KIND })
          const identity = randomIdentity()
          let counter = 0
          const run = async (provider: StoreProvider) => {
            const coordinator = createVaultCoordinator({
              ...policy,
              mode: 'replicated',
              identity,
              signer: identity,
              principal: identity.id,
              store: await getVaultStore(provider),
              runtime: createRuntime(),
              authority: { authorize: async () => true },
              nextHLC: async () =>
                `2026-10-01T00:00:00.000Z:${String(++counter).padStart(8, '0')}:yield`,
              records: {
                opKind: VAULT_OP_KIND,
                yield: policy.recordsYield,
                nowMS: () => Date.parse('2026-10-01T01:00:00Z'),
                maxDriftMS: 60000,
                validateConsumerMetadata: async () => true,
              },
            })
            const assertScope = () => {
              expect(writer.timers > 0).toBe(
                ambient && (policy.yield ?? policy.recordsYield) !== false,
              )
              if ((policy.yield ?? policy.recordsYield) === false)
                expect(timers).not.toHaveBeenCalled()
            }
            clearMemos()
            const key = await coordinator.createKey({ ownerDID: identity.id })
            assertScope()
            clearMemos()
            const entry = await coordinator.putEntry({
              ...key,
              entryID: 'entry',
              kind: 'blob',
              label: 'Secret',
              attributes: {},
              plaintext: new Uint8Array([1, 2, 3]),
            })
            assertScope()
            clearMemos()
            await expect(
              coordinator.putEntry({
                ...key,
                entryID: 'entry',
                kind: 'blob',
                label: 'Secret',
                attributes: {},
                plaintext: new Uint8Array([9]),
              }),
            ).rejects.toBeInstanceOf(VaultWriteConflict)
            expect(timers).not.toHaveBeenCalled()
            clearMemos()
            await coordinator.lockAll({ ownerDID: identity.id })
            expect(timers).not.toHaveBeenCalled()
            clearMemos()
            expect(await coordinator.readEntry(entry)).toEqual(new Uint8Array([1, 2, 3]))
            assertScope()
            clearMemos()
            const stored = await coordinator.records.adapter.get({
              type: 'vault.key',
              owner: key.ownerDID,
              id: key.keyID,
            })
            expect(stored).toMatchObject({ key: { id: key.keyID } })
            expect(timers.mock.calls.length > 0).toBe(
              (policy.yield ?? policy.recordsYield) !== false,
            )
            const record = stored?.copies[0]
            if (record === undefined) throw new Error('Missing record')
            const op = await verifySignedRecord({ record, opKind: VAULT_OP_KIND, yield: false })
            if (op === null) throw new Error('Invalid record')
            const hlc = `2026-10-01T00:00:00.000Z:${String(++counter).padStart(8, '0')}:yield`
            const candidate = {
              ...record,
              hlc,
              ...(await signRecordOp({
                identity,
                claim: { ...op.claim, hlc },
                opKind: VAULT_OP_KIND,
                yield: false,
              })),
            }
            clearMemos()
            expect(await coordinator.records.apply({ records: [candidate] })).toMatchObject({
              rejected: [],
              parked: [],
            })
            assertScope()
          }
          if (ambient) await db.withTransaction(run)
          else await run(db)
        } finally {
          await db.close()
          driverSpy.mockRestore()
          expect(writer.connections.size).toBe(0)
          await harness.cleanup()
        }
      })
    }
  }
}
