import { normalizeDID, randomIdentity, type SigningIdentity } from '@kokuin/token'
import { HLC } from '@sozai/hlc'
import { describe, expect, test, vi } from 'vitest'

import {
  applyRecordChunk,
  getRecordDecisions,
  type RecordDecisionMap,
  type RecordKey,
  type RecordStoreAdapter,
  type RecordTypeDefinition,
  recordKeyText,
  recordPayloadDigest,
  type SignedRecord,
  signRecordOp,
} from '../src/index.js'
import { decisionOf } from './decision-fixture.js'

const TEST_OP_KIND = 'test/record-op'

const NOW = Date.now()

async function makeRecord(
  identity: SigningIdentity,
  id: string,
  type = 'test.value',
): Promise<SignedRecord> {
  const payload = new Uint8Array([1])
  const claim = {
    type,
    id,
    owner: normalizeDID(identity.id),
    hlc: HLC.serialize({ wallTime: NOW, counter: 0, nodeID: identity.id }),
    payloadDigest: recordPayloadDigest(payload),
    deleted: false,
    meta: {},
  }
  const signed = await signRecordOp(identity, claim, TEST_OP_KIND)
  return { type: claim.type, id, owner: claim.owner, hlc: claim.hlc, payload, ...signed }
}

function valueType(overrides: Partial<RecordTypeDefinition> = {}): RecordTypeDefinition {
  return {
    type: 'test.value',
    policy: { kind: 'lww' },
    dependsOn: [],
    authorize: async () => true,
    dependencies: () => [],
    ...overrides,
  }
}

/** A memory store with `getMany`, logging each read and lock with the adapter that served it. */
function batchStore(initial: ReadonlyArray<SignedRecord> = []) {
  const rows = new Map(initial.map((record) => [recordKeyText(record), record]))
  const events: Array<string> = []
  const over = (scope: 'store' | 'tx'): RecordStoreAdapter => {
    const adapter: RecordStoreAdapter = {
      transaction: async (fn) => await fn(over('tx')),
      get: vi.fn(async (key: RecordKey) => {
        events.push(`${scope}:get`)
        const record = rows.get(recordKeyText(key))
        return record === undefined ? null : decisionOf(record)
      }),
      getMany: vi.fn(async (keys: ReadonlyArray<RecordKey>) => {
        events.push(`${scope}:getMany:${keys.length}`)
        const decisions: RecordDecisionMap = new Map()
        for (const key of keys) {
          const record = rows.get(recordKeyText(key))
          if (record !== undefined) decisions.set(recordKeyText(key), decisionOf(record))
        }
        return decisions
      }),
      list: async () => [],
      putCopy: async (record) => {
        rows.set(recordKeyText(record), record)
      },
      pruneCopy: async () => {},
      lock: async () => {
        events.push(`${scope}:lock`)
      },
    }
    return adapter
  }
  return { store: over('store'), events }
}

describe('getRecordDecisions', () => {
  test('falls back to one get per distinct key and leaves missing keys out', async () => {
    const identity = randomIdentity()
    const held = await makeRecord(identity, 'held')
    const missing = { type: 'test.value', owner: held.owner, id: 'missing' }
    const get = vi.fn(async (key: RecordKey) => (key.id === 'held' ? decisionOf(held) : null))
    const store: RecordStoreAdapter = {
      transaction: async (fn) => await fn(store),
      get,
      list: async () => [],
      putCopy: async () => {},
      pruneCopy: async () => {},
    }
    const decisions = await getRecordDecisions(store, [held, missing, held])
    expect(get).toHaveBeenCalledTimes(2)
    expect([...decisions.keys()]).toEqual([recordKeyText(held)])
    expect(decisions.get(recordKeyText(held))).toEqual(decisionOf(held))
  })

  test('reads distinct keys through getMany once and never calls get', async () => {
    const identity = randomIdentity()
    const held = await makeRecord(identity, 'held')
    const { store, events } = batchStore([held])
    const decisions = await getRecordDecisions(store, [held, held])
    expect(events).toEqual(['store:getMany:1'])
    expect(store.get).not.toHaveBeenCalled()
    expect(decisions.size).toBe(1)
  })

  test('reads nothing for no keys', async () => {
    const { store, events } = batchStore()
    expect((await getRecordDecisions(store, [])).size).toBe(0)
    expect(events).toEqual([])
  })
})

describe('applyRecordChunk reads the store in batches', () => {
  test('prefetches once before the locks and rechecks once under them', async () => {
    const identity = randomIdentity()
    const records = await Promise.all(
      Array.from({ length: 20 }, (_, index) => makeRecord(identity, `r${index}`)),
    )
    const { store, events } = batchStore()
    const result = await applyRecordChunk({
      opKind: TEST_OP_KIND,
      records,
      store,
      types: new Map([
        [
          'test.value',
          valueType({ lockKeys: (record) => [{ type: record.type, key: record.id }] }),
        ],
      ]),
      nowMS: NOW,
      maxDriftMS: 60_000,
      receiveClock: () => {},
      resolveController: async () => null,
      verifyCapability: async () => false,
    })
    expect(result.applied).toBe(20)
    // No per-key read outside the transaction, and the recheck follows the lock.
    expect(events.filter((event) => event.startsWith('store:'))).toEqual(['store:getMany:20'])
    const lock = events.indexOf('tx:lock')
    expect(events.slice(lock, lock + 2)).toEqual(['tx:lock', 'tx:getMany:20'])
    expect(events.filter((event) => event === 'tx:getMany:20')).toHaveLength(1)
  })

  test('checks refused records for replays in one read, keeping rejection order', async () => {
    const identity = randomIdentity()
    const [first, replay, last] = await Promise.all(
      ['a', 'b', 'c'].map((id) => makeRecord(identity, id)),
    )
    const { store, events } = batchStore([replay as SignedRecord])
    const result = await applyRecordChunk({
      opKind: TEST_OP_KIND,
      records: [first, replay, last] as Array<SignedRecord>,
      store,
      types: new Map([['test.value', valueType({ precheck: async () => false })]]),
      nowMS: NOW,
      maxDriftMS: 60_000,
      receiveClock: () => {},
      resolveController: async () => null,
      verifyCapability: async () => false,
    })
    expect(result.rejected).toEqual([
      { record: first, reason: 'unauthorized' },
      { record: last, reason: 'unauthorized' },
    ])
    expect(events).toEqual(['store:getMany:3'])
  })

  test('reads decisions for records and dependencies once, and sees records stored earlier', async () => {
    const identity = randomIdentity()
    const parentRecord = await makeRecord(identity, 'p', 'test.parent')
    const children = await Promise.all(
      Array.from({ length: 20 }, (_, index) => makeRecord(identity, `c${index}`)),
    )
    const parentKey = { type: 'test.parent', owner: parentRecord.owner, id: 'p' }
    const seen: Array<boolean> = []
    const types = new Map([
      ['test.parent', valueType({ type: 'test.parent' })],
      [
        'test.value',
        valueType({
          dependsOn: ['test.parent'],
          dependencies: () => [parentKey],
          authorize: async (_op, ctx) => {
            const decision = await (ctx.decision ?? ((key) => ctx.store.get(key)))(parentKey)
            seen.push(decision !== null)
            return decision !== null
          },
        }),
      ],
    ])
    const run = async (store: RecordStoreAdapter) => {
      seen.length = 0
      return await applyRecordChunk({
        opKind: TEST_OP_KIND,
        // The parent arrives last; type order stores it first.
        records: [...children, parentRecord],
        store,
        types,
        nowMS: NOW,
        maxDriftMS: 60_000,
        receiveClock: () => {},
        resolveController: async () => null,
        verifyCapability: async () => false,
      })
    }

    const { store, events } = batchStore()
    const result = await run(store)
    expect(result).toEqual({ applied: 21, parked: [], rejected: [], conflicts: [] })
    expect(seen).toEqual(children.map(() => true))
    // One batched read inside the transaction covers 21 records and their shared dependency.
    expect(events.filter((event) => event.startsWith('tx:'))).toEqual(['tx:getMany:21'])

    // Without getMany, the same chunk falls back to one read per distinct key.
    const { store: plain } = batchStore()
    const fallback: RecordStoreAdapter = { ...plain, getMany: undefined }
    fallback.transaction = async (fn) => await fn(fallback)
    expect(await run(fallback)).toEqual({ applied: 21, parked: [], rejected: [], conflicts: [] })
    expect(seen).toEqual(children.map(() => true))
  })
})
