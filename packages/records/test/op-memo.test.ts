import type * as Token from '@kokuin/token'
import {
  type MethodRegistry,
  normalizeDID,
  randomIdentity,
  resolveIssuerWithDoc,
  type SigningIdentity,
} from '@kokuin/token'
import { HLC } from '@sozai/hlc'
import { afterEach, describe, expect, test, vi } from 'vitest'

import {
  applyRecordChunk,
  createRecordVerifier,
  type RecordDecisionMap,
  type RecordKey,
  type RecordStoreAdapter,
  recordKeyText,
  recordPayloadDigest,
  type SignedRecord,
  signRecordOp,
  verifyRecordOp,
} from '../src/index.js'
import { clearRecordOpMemo } from '../src/op.js'
import { decisionOf } from './decision-fixture.js'

const verifications = vi.hoisted(() => ({ count: 0 }))

vi.mock('@kokuin/token', async (importOriginal) => {
  const actual = await importOriginal<typeof Token>()
  return {
    ...actual,
    verifyToken: new Proxy(actual.verifyToken, {
      apply(target, self, args) {
        verifications.count += 1
        return Reflect.apply(target, self, args)
      },
    }),
  }
})

const TEST_OP_KIND = 'test/record-op'

const NOW = Date.now()

// Resolves did:key itself, but through the registry: as a resolved method, its keys could rotate.
const registry: MethodRegistry = [
  {
    method: 'key',
    resolve: async (did, header) => await resolveIssuerWithDoc({ iss: did, header }),
  },
]

async function makeRecord(
  identity: SigningIdentity,
  id: string,
  options: { owner?: string; wallTime?: number } = {},
): Promise<SignedRecord> {
  const payload = new Uint8Array([1])
  const claim = {
    type: 'test.value',
    id,
    owner: options.owner ?? normalizeDID(identity.id),
    hlc: HLC.serialize({ wallTime: options.wallTime ?? NOW, counter: 0, nodeID: identity.id }),
    payloadDigest: recordPayloadDigest(payload),
    deleted: false,
    meta: { label: id },
  }
  const signed = await signRecordOp(identity, claim, TEST_OP_KIND)
  return { type: claim.type, id, owner: claim.owner, hlc: claim.hlc, payload, ...signed }
}

function storeOf(initial: ReadonlyArray<SignedRecord>): RecordStoreAdapter {
  const rows = new Map(initial.map((record) => [recordKeyText(record), record]))
  const store: RecordStoreAdapter = {
    transaction: async (fn) => await fn(store),
    get: async (key: RecordKey) => {
      const record = rows.get(recordKeyText(key))
      return record === undefined ? null : decisionOf(record)
    },
    getMany: async (keys) => {
      const decisions: RecordDecisionMap = new Map()
      for (const key of keys) {
        const record = rows.get(recordKeyText(key))
        if (record !== undefined) decisions.set(recordKeyText(key), decisionOf(record))
      }
      return decisions
    },
    list: async () => [],
    putCopy: async (record) => {
      rows.set(recordKeyText(record), record)
    },
    pruneCopy: async () => {},
  }
  return store
}

describe('record op verification memo', () => {
  afterEach(() => {
    clearRecordOpMemo()
    verifications.count = 0
  })

  test('a self-certifying op verifies once across calls, and each call gets its own copy', async () => {
    const record = await makeRecord(randomIdentity(), 'a')
    const first = await verifyRecordOp(record.opJWT, TEST_OP_KIND)
    if (first === null) throw new Error('expected a verified op')
    first.claim.meta.label = 'changed'
    const second = await verifyRecordOp(record.opJWT, TEST_OP_KIND)

    expect(verifications.count).toBe(1)
    expect(second?.claim.meta.label).toBe('a')
    expect(second?.opHash).toBe(record.opHash)
  })

  test('another op kind, a refusal and a registry-resolved issuer are never answered from memory', async () => {
    const record = await makeRecord(randomIdentity(), 'a')

    expect(await verifyRecordOp(record.opJWT, TEST_OP_KIND)).not.toBeNull()
    expect(await verifyRecordOp(record.opJWT, 'test/other-kind')).toBeNull()
    expect(await verifyRecordOp(record.opJWT, 'test/other-kind')).toBeNull()
    expect(await verifyRecordOp(record.opJWT, TEST_OP_KIND, registry)).not.toBeNull()
    expect(await verifyRecordOp(record.opJWT, TEST_OP_KIND, registry)).not.toBeNull()
    expect(verifications.count).toBe(5)
  })

  test('a scoped verifier checks each token once, whatever the issuer, and binds the record', async () => {
    const record = await makeRecord(randomIdentity(), 'a')
    const verify = createRecordVerifier(TEST_OP_KIND, registry)

    expect(await verify(record)).not.toBeNull()
    expect(await verify(record)).not.toBeNull()
    expect(await verify({ ...record, id: 'b' })).toBeNull()
    expect(verifications.count).toBe(1)
  })

  test('apply verifies a registry-resolved token once before the locks and once under them', async () => {
    const identity = randomIdentity()
    const records = await Promise.all(['a', 'b', 'c'].map((id) => makeRecord(identity, id)))
    const apply = async () => {
      return await applyRecordChunk({
        opKind: TEST_OP_KIND,
        // Replays: each token is the incoming record, a prefetched copy and a stored snapshot.
        records,
        store: storeOf(records),
        types: new Map([
          [
            'test.value',
            {
              type: 'test.value',
              policy: { kind: 'lww' },
              dependsOn: [],
              authorize: async () => true,
              dependencies: () => [],
            },
          ],
        ]),
        nowMS: NOW,
        maxDriftMS: 60_000,
        receiveClock: () => {},
        methods: registry,
        resolveController: async () => null,
        verifyCapability: async () => false,
      })
    }

    expect(await apply()).toEqual({ applied: 0, parked: [], rejected: [], conflicts: [] })
    // Three tokens: each verified as the incoming record and prefetched copy before the locks,
    // then once more as the stored snapshot under them.
    expect(verifications.count).toBe(6)
    // A second call verifies again: no scope outlives a call.
    await apply()
    expect(verifications.count).toBe(12)
  })

  test('a resolved key removed between the pre-lock read and the lock is not honoured', async () => {
    const removed = new Set<string>()
    const rotating: MethodRegistry = [
      {
        method: 'key',
        resolve: async (did, header) => {
          if (removed.has(did)) throw new Error(`Key removed: ${did}`)
          return await resolveIssuerWithDoc({ iss: did, header })
        },
      },
    ]
    const owner = randomIdentity()
    const writer = randomIdentity()
    // A newer stored op, signed by another writer the owner admitted, would win the merge.
    const stored = await makeRecord(writer, 'a', { owner: normalizeDID(owner.id) })
    const incoming = await makeRecord(owner, 'a', { wallTime: NOW - 1000 })
    const store = storeOf([stored])
    // Locking is the moment between the pre-lock read and the authoritative reads.
    store.lock = async () => {
      removed.add(writer.id)
    }
    const result = await applyRecordChunk({
      opKind: TEST_OP_KIND,
      records: [incoming],
      store,
      types: new Map([
        [
          'test.value',
          {
            type: 'test.value',
            policy: { kind: 'lww' },
            dependsOn: [],
            authorize: async () => true,
            dependencies: () => [],
            lockKeys: (record) => [{ type: record.type, key: record.id }],
          },
        ],
      ]),
      nowMS: NOW,
      maxDriftMS: 60_000,
      receiveClock: () => {},
      methods: rotating,
      resolveController: async () => null,
      verifyCapability: async () => false,
    })

    // Under the lock the stored op no longer verifies, so it is no record and the older op applies.
    expect(result).toEqual({ applied: 1, parked: [], rejected: [], conflicts: [] })
  })
})
