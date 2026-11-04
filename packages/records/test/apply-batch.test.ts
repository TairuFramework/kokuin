import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { createSigningIdentity } from '@kokuin/token'
import { fromB64U, toB64U } from '@sozai/codec'
import { HLC } from '@sozai/hlc'
import { beforeEach, expect, test } from 'vitest'

import { applyRecordChunk } from '../src/apply.js'
import { clearRecordOpMemo, signRecordOp, verifySignedRecord } from '../src/op.js'
import type { SignedRecord } from '../src/record.js'
import type { RecordStoreAdapter } from '../src/store.js'
import { claimFixture } from './crypto-fixture.js'

const identity = createSigningIdentity(new Uint8Array(32).fill(7))

async function records(prefix = ''): Promise<Array<SignedRecord>> {
  return Promise.all(
    ['a', 'b', 'c'].map(async (id) => {
      const claim = {
        ...claimFixture,
        id: `${prefix}${id}`,
        hlc: HLC.serialize({ wallTime: Date.parse('2026-01-01'), counter: 0, nodeID: 'node' }),
      }
      return {
        ...claim,
        payload: new Uint8Array([1, 2, 3]),
        ...(await signRecordOp(identity, claim, 'test/op')),
      }
    }),
  )
}

function countingProvider(overrides: Partial<CryptoProvider> = {}) {
  const batches: Array<number> = []
  let singles = 0
  const crypto: CryptoProvider = {
    ...nobleCrypto,
    async verify(...args) {
      singles++
      return nobleCrypto.verify(...args)
    },
    async verifyBatch(items) {
      batches.push(items.length)
      return nobleCrypto.verifyBatch(items)
    },
    ...overrides,
  }
  return { crypto, batches, singles: () => singles }
}

function apply(rows: Array<SignedRecord>, crypto: CryptoProvider) {
  const written: Array<SignedRecord> = []
  const store: RecordStoreAdapter = {
    async get() {
      return null
    },
    async list() {
      return []
    },
    async putCopy(row) {
      written.push(row)
    },
    async pruneCopy() {},
    async transaction(fn) {
      return fn(store)
    },
  }
  const pending = applyRecordChunk({
    records: rows,
    crypto,
    store,
    opKind: 'test/op',
    types: new Map([
      [
        'test.value',
        {
          type: 'test.value',
          policy: { kind: 'lww' },
          dependsOn: [],
          dependencies: () => [],
          authorize: async () => true,
        },
      ],
    ]),
    nowMS: Date.parse('2026-01-01'),
    maxDriftMS: 1000,
    receiveClock: () => {},
    resolveController: async () => null,
    verifyCapability: async () => true,
  })
  return { pending, written }
}

beforeEach(clearRecordOpMemo)

test('screening batches three cold ops and shares duplicate in-flight ops', async () => {
  const rows = await records()
  const p = countingProvider()
  const result = await apply([...rows, ...rows], p.crypto).pending
  expect(result.rejected).toEqual([])
  expect(result.applied).toBe(3)
  expect({ batches: p.batches, singles: p.singles() }).toEqual({ batches: [3], singles: 0 })
})

test('mixed signatures retain individual decisions and only successes enter the op memo', async () => {
  const rows = await records()
  const bad = rows[1]
  if (bad === undefined) throw new Error('Missing fixture')
  const parts = bad.opJWT.split('.')
  const signature = fromB64U(parts[2] ?? '')
  signature[0] = (signature[0] ?? 0) ^ 1
  bad.opJWT = `${parts[0]}.${parts[1]}.${toB64U(signature)}`
  const p = countingProvider()
  const first = await apply(rows, p.crypto).pending
  expect(first.applied).toBe(2)
  expect(first.rejected.map(({ record, reason }) => [record.id, reason])).toEqual([
    ['b', 'signature'],
  ])
  expect(p.batches).toEqual([3])
  expect(p.singles()).toBe(0)
  const second = await apply(rows, p.crypto).pending
  expect(second).toEqual(first)
  expect(p.batches).toEqual([3])
  expect(p.singles()).toBe(1)
})

test('the selected provider owns warm ops across chunks and direct callers', async () => {
  const rows = await records()
  const p = countingProvider()
  for (const row of rows)
    expect(await verifySignedRecord(row, 'test/op', undefined, p)).not.toBeNull()
  expect(p.singles()).toBe(3)
  await apply(rows, p.crypto).pending
  expect(p.batches).toEqual([])
  expect(p.singles()).toBe(3)
  const other = countingProvider({
    async verifyBatch(items) {
      return items.map(() => false)
    },
  })
  expect((await apply(rows, other.crypto).pending).rejected).toHaveLength(3)
  expect(other.singles()).toBe(0)
  const fresh = countingProvider()
  await apply(rows, fresh.crypto).pending
  await apply(rows, fresh.crypto).pending
  for (const row of rows)
    expect(await verifySignedRecord(row, 'test/op', undefined, fresh)).not.toBeNull()
  expect(fresh.batches).toEqual([3])
  expect(fresh.singles()).toBe(0)
})

test('batch failures escape unchanged without fallback or success memoisation', async () => {
  const rows = await records()
  const sentinel = new Error('batch unavailable')
  let failures = 0
  let failing = true
  const p = countingProvider({
    async verifyBatch(items) {
      failures++
      if (failing) throw sentinel
      return nobleCrypto.verifyBatch(items)
    },
  })
  for (let attempt = 0; attempt < 2; attempt++) {
    const call = apply(rows, p.crypto)
    await expect(call.pending).rejects.toBe(sentinel)
    expect(call.written).toEqual([])
  }
  expect(failures).toBe(2)
  expect(p.singles()).toBe(0)
  failing = false
  expect((await apply(rows, p.crypto).pending).applied).toBe(3)
  expect(failures).toBe(3)
})

test('one cold op retains a single verification call', async () => {
  const rows = (await records()).slice(0, 1)
  const p = countingProvider()
  expect((await apply(rows, p.crypto).pending).applied).toBe(1)
  expect(p.batches).toEqual([])
  expect(p.singles()).toBe(1)
})

test('batched screening owns payloads and bindings before provider suspension', async () => {
  const rows = await records()
  const originals = structuredClone(rows)
  let release = () => {}
  let entered = () => {}
  const waiting = new Promise<void>((resolve) => {
    release = resolve
  })
  const started = new Promise<void>((resolve) => {
    entered = resolve
  })
  const p = countingProvider({
    async verifyBatch(items) {
      entered()
      await waiting
      return nobleCrypto.verifyBatch(items)
    },
  })
  const call = apply(rows, p.crypto)
  await started
  for (const row of rows) {
    row.payload?.fill(9)
    row.id = 'changed'
    row.opJWT = 'changed'
  }
  release()
  expect((await call.pending).applied).toBe(3)
  expect(call.written).toEqual(originals)
})

test('sequential cold chunks each dispatch their own batch', async () => {
  const p = countingProvider()
  await apply(await records('first-'), p.crypto).pending
  await apply(await records('second-'), p.crypto).pending
  expect(p.batches).toEqual([3, 3])
  expect(p.singles()).toBe(0)
})

test('token memo survives sequential chunks after the op memo is cleared', async () => {
  const rows = await records('token-warm-')
  const p = countingProvider()
  expect((await apply(rows, p.crypto).pending).applied).toBe(3)
  expect(p.batches).toEqual([3])
  clearRecordOpMemo()
  expect((await apply(rows, p.crypto).pending).applied).toBe(3)
  expect({ batches: p.batches, singles: p.singles() }).toEqual({ batches: [3], singles: 0 })
  clearRecordOpMemo()
  for (const row of rows) {
    expect(await verifySignedRecord(row, 'test/op', undefined, p)).not.toBeNull()
  }
  expect({ batches: p.batches, singles: p.singles() }).toEqual({ batches: [3], singles: 0 })
})
