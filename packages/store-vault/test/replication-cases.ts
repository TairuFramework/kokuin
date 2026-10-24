import { sql, withKeyLock, withKeyLocks } from '@hozon/db'
import type { RecordStoreAdapter, SignedRecord, VerifiedRecordOp } from '@kokuin/records'
import {
  canonicalRecordClaim,
  fingerprintRange,
  rangeLeaf,
  recordClaimDigest,
  recordDecisionDigest,
  recordKeyText,
  recordPayloadDigest,
  signRecordOp,
  verifySignedRecord,
} from '@kokuin/records'
import type { SigningIdentity } from '@kokuin/token'
import { createIdentity, normalizeDID, randomIdentity, stringifyToken } from '@kokuin/token'
import type {
  CredentialAuthority,
  CredentialAuthorityRequest,
  VaultRecordType,
} from '@kokuin/vault'
import {
  createVaultKeyID,
  encodeVaultRecordPayload,
  getSuite,
  selectWinningBranch,
  vaultRevocationRecordID,
} from '@kokuin/vault'
import { ed25519 } from '@noble/curves/ed25519.js'
import { blake3 } from '@noble/hashes/blake3.js'
import { fromB64U, fromUTF, toB64U } from '@sozai/codec'
import { createRuntime } from '@sozai/runtime'
import { afterAll, afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

import type { VaultRecords, VaultRecordsParams } from '../src/index.js'
import {
  createVaultRecords,
  getVaultRecordsStore,
  getVaultStore,
  VaultModeConflict,
  VaultRecordRowError,
  VaultWriteConflict,
  vaultRecordsStoreDefinition,
} from '../src/index.js'
import type { StoreHarness } from './cases.js'
import { openVaultTestDB, stamp, storedEntry } from './cases.js'

const OP_KIND = 'kokuin/vault-op/v1'
const TYPES: Array<VaultRecordType> = [
  'vault.key',
  'vault.key-branch',
  'vault.wrapping',
  'vault.entry',
  'vault.revocation',
]
const UNIQUE = new Uint8Array(16).fill(7)

async function signed(
  signer: SigningIdentity,
  params: {
    type: VaultRecordType
    id: string
    owner: string
    hlc: string
    payload: Uint8Array | null
    meta: Record<string, unknown>
  },
  opKind = OP_KIND,
): Promise<SignedRecord> {
  const { payload, ...claim } = params
  return {
    type: params.type,
    id: params.id,
    owner: params.owner,
    hlc: params.hlc,
    payload,
    ...(await signRecordOp(
      signer,
      {
        ...claim,
        payloadDigest: recordPayloadDigest(payload),
        deleted: payload === null,
      },
      opKind,
    )),
  }
}

async function verified(record: SignedRecord): Promise<VerifiedRecordOp> {
  const op = await verifySignedRecord(record, OP_KIND)
  if (op === null) throw new Error('fixture signature did not verify')
  return op
}

async function resign(signer: SigningIdentity, record: SignedRecord): Promise<SignedRecord> {
  const op = await verified(record)
  return { ...record, ...(await signRecordOp(signer, op.claim, OP_KIND)) }
}

async function chain(
  signer: SigningIdentity,
  params: {
    version?: number
    counter?: number
    owner?: string
    state?: 'active' | 'retired'
    consumer?: Record<string, unknown>
  } = {},
) {
  const owner = params.owner ?? signer.id
  const keyID = createVaultKeyID(owner, UNIQUE)
  const version = params.version ?? 1
  const hlc = stamp(params.counter ?? version * 10)
  const state = params.state ?? 'active'
  const consumer = params.consumer ?? {}
  const key = await signed(signer, {
    type: 'vault.key',
    id: keyID,
    owner,
    hlc,
    payload: encodeVaultRecordPayload('vault.key', { suite: 1, state }),
    meta: { keyID, keyUnique: toB64U(UNIQUE), version, state, consumer },
  })
  const branchID = `${key.hlc}:${key.opHash}`
  const payload = encodeVaultRecordPayload('vault.key-branch', {
    authorDID: signer.id,
    hlc,
    opJWT: key.opJWT,
    opHash: key.opHash,
    suite: 1,
  })
  const recordID = recordPayloadDigest(payload)
  if (recordID === null) throw new Error('branch payload has no digest')
  const branch = await signed(signer, {
    type: 'vault.key-branch',
    id: recordID,
    owner,
    hlc,
    payload,
    meta: { keyID, keyVersion: version, branchID, consumer },
  })
  return { key, branch, branchID, address: { ownerDID: owner, keyID }, version }
}

type Chain = Awaited<ReturnType<typeof chain>>

async function dependent(
  signer: SigningIdentity,
  source: Chain,
  type: 'vault.entry' | 'vault.wrapping',
  options: {
    id?: string
    counter?: number
    contentCounter?: number
    recipient?: string | null
    factorRecipient?: string
    deleted?: boolean
    consumer?: Record<string, unknown>
  } = {},
): Promise<SignedRecord> {
  const hlc = stamp(options.counter ?? 100)
  const wrapped =
    type === 'vault.wrapping' && !options.deleted
      ? await getSuite(1).wrap({
          runtime: createRuntime(),
          contentKey: new Uint8Array(32).fill(7),
          keyID: source.address.keyID,
          keyVersion: source.version,
          wrappingID: options.id ?? 'shared-wrapping',
          factors: [{ kind: 'did', recipientDID: options.factorRecipient ?? signer.id }],
        })
      : null
  const payload = options.deleted
    ? null
    : type === 'vault.entry'
      ? encodeVaultRecordPayload('vault.entry', {
          iv: new Uint8Array(12),
          ciphertext: new Uint8Array([0x80, 0xff, 0x00]),
        })
      : wrapped === null
        ? null
        : encodeVaultRecordPayload('vault.wrapping', wrapped)
  return await signed(signer, {
    type,
    id: options.id ?? (type === 'vault.entry' ? 'shared-entry' : 'shared-wrapping'),
    owner: source.address.ownerDID,
    hlc,
    payload,
    meta: {
      keyID: source.address.keyID,
      keyVersion: source.version,
      branchID: source.branchID,
      branchRecordID: source.branch.id,
      consumer: options.consumer ?? {},
      ...(type === 'vault.entry'
        ? {
            contentHLC: stamp(options.contentCounter ?? 90),
            kind: 'blob',
            label: 'State',
            attributes: {},
          }
        : { recipient: options.recipient === undefined ? signer.id : options.recipient }),
    },
  })
}

// The consumer owns this in-memory transport. The wire contains signed records, never a second policy.
async function exchange(source: RecordStoreAdapter, receiver: VaultRecords, context?: unknown) {
  const records = (await source.list(TYPES)).flatMap((decision) => decision.copies)
  return await receiver.apply(structuredClone(records), context)
}

export function replicationCases(harness: StoreHarness): void {
  describe(`vault record exchange (${harness.name})`, () => {
    type Peer = Awaited<ReturnType<typeof openVaultTestDB>> & { records: VaultRecords }
    let peers: Array<Peer>
    let left: Peer
    let right: Peer
    let owner: SigningIdentity
    let authority: CredentialAuthority
    const metadata = vi.fn(async () => true)

    async function peer(policy = authority): Promise<Peer> {
      const opened = await openVaultTestDB(harness, true)
      const records = createVaultRecords({
        store: opened.store,
        opKind: OP_KIND,
        authority: policy,
        validateConsumerMetadata: metadata,
        nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
        maxDriftMS: 60_000,
      })
      const result = { ...opened, records }
      peers.push(result)
      return result
    }

    beforeEach(async () => {
      peers = []
      metadata.mockClear()
      authority = { authorize: vi.fn(async () => true) }
      owner = randomIdentity()
      left = await peer()
      right = await peer()
    })
    afterEach(async () => {
      for (const peer of peers)
        expect(peer.queries.every((query) => query.parameters.length <= 500)).toBe(true)
      await Promise.all(peers.map(async ({ db }) => await db.close()))
    })
    afterAll(async () => {
      await harness.cleanup()
    })

    async function seed(source: Chain) {
      const result = await left.records.apply([source.key, source.branch])
      expect(result.rejected).toEqual([])
      expect(result.parked).toEqual([])
      expect((await exchange(left.records.adapter, right.records)).rejected).toEqual([])
    }

    test('batch reads equal individual owner-qualified reads and deduplicate keys', async () => {
      const source = await chain(owner)
      await seed(source)
      const entry = await dependent(owner, source, 'vault.entry')
      await left.records.apply([entry])
      const keys = [
        source.key,
        source.branch,
        entry,
        entry,
        { ...entry, owner: randomIdentity().id },
        { ...entry, id: 'absent' },
      ]
      const start = left.queries.length
      const many = await left.records.adapter.getMany?.(keys)
      expect(
        left.queries.slice(start).filter((q) => /select .*vault_records/i.test(q.sql)),
      ).toHaveLength(1)
      const expected = new Map()
      for (const key of keys) {
        const decision = await left.records.adapter.get(key)
        if (decision !== null) expected.set(recordKeyText(key), decision)
      }
      expect(many).toEqual(expected)
      expect(many?.size).toBe(3)
    })

    test('batch reads chunk large addresses without exceeding the parameter ceiling', async () => {
      const keys = Array.from({ length: 501 }, (_, i) => ({
        type: 'vault.entry',
        owner: owner.id,
        id: `absent-${i}`,
      }))
      const start = left.queries.length
      expect((await left.records.adapter.getMany?.(keys))?.size).toBe(0)
      const queries = left.queries.slice(start).filter((q) => /select .*vault_records/i.test(q.sql))
      expect(queries.length).toBeGreaterThan(1)
      expect(queries.every((q) => q.parameters.length <= 500)).toBe(true)
    })

    test('records and projections survive adapter reconstruction and remain owner-qualified', async () => {
      const source = await chain(owner)
      await seed(source)
      const entry = await dependent(owner, source, 'vault.entry')
      await left.records.apply([entry])
      const reopened = createVaultRecords({
        store: left.store,
        opKind: OP_KIND,
        authority,
        validateConsumerMetadata: metadata,
        nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
        maxDriftMS: 60_000,
      })
      expect((await reopened.adapter.get(entry))?.copies).toEqual([entry])
      expect(await reopened.adapter.get({ ...entry, owner: randomIdentity().id })).toBeNull()
      expect(
        (await left.store.getEntry({ ownerDID: owner.id, entryID: entry.id }))?.provenance,
      ).toBe(source.branchID)
      expect(
        (await reopened.listKeyBranches({ ...source.address, keyVersion: 1 }))[0]?.branchID,
      ).toBe(source.branchID)
    })

    test('host rollback removes decisions, projections and candidate effects together', async () => {
      const source = await chain(owner)
      await seed(source)
      const entry = await dependent(owner, source, 'vault.entry')
      await expect(
        left.store.transaction(async (store) => {
          const records = createVaultRecords({
            store,
            opKind: OP_KIND,
            authority,
            validateConsumerMetadata: metadata,
            nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
            maxDriftMS: 60_000,
          })
          await records.apply([entry])
          expect((await store.getEntry({ ownerDID: owner.id, entryID: entry.id }))?.hlc).toBe(
            entry.hlc,
          )
          throw new Error('abort host')
        }),
      ).rejects.toThrow('abort host')
      expect(await left.records.adapter.get(entry)).toBeNull()
      expect(await left.records.listEntryCandidates({ ...source.address, keyVersion: 1 })).toEqual(
        [],
      )
      expect(await left.store.getEntry({ ownerDID: owner.id, entryID: entry.id })).toBeUndefined()
    })

    test.each(['payload', 'deleted', 'meta'] as const)(
      'corrupt stored %s fails closed in get, batch reads and apply',
      async (field) => {
        const source = await chain(owner)
        await seed(source)
        const entry = await dependent(owner, source, 'vault.entry')
        await left.records.apply([entry])
        const table = sql.table('vault_records')
        if (field === 'payload')
          await sql`update ${table} set payload = ${left.db.adapter.encodeBinary(new Uint8Array([255]))} where id = ${entry.id}`.execute(
            left.raw,
          )
        if (field === 'deleted')
          await sql`update ${table} set deleted = 7 where id = ${entry.id}`.execute(left.raw)
        if (field === 'meta')
          await sql`update ${table} set meta = ${JSON.stringify({ corrupt: true })} where id = ${entry.id}`.execute(
            left.raw,
          )
        await expect(left.records.adapter.get(entry)).rejects.toThrow(VaultRecordRowError)
        await expect(left.records.adapter.getMany?.([source.key, entry])).rejects.toThrow(
          VaultRecordRowError,
        )
        await expect(
          left.records.apply([await dependent(owner, source, 'vault.entry', { counter: 200 })]),
        ).rejects.toThrow(VaultRecordRowError)
      },
    )

    test('malformed signed payload and altered payload leave no candidate or projection', async () => {
      const source = await chain(owner)
      await seed(source)
      const entry = await dependent(owner, source, 'vault.entry')
      const op = await verified(entry)
      const malformed = await signed(owner, {
        ...op.claim,
        type: 'vault.entry',
        payload: fromUTF('{}'),
      })
      expect((await left.records.apply([malformed])).rejected).toHaveLength(1)
      expect(
        (await left.records.apply([{ ...entry, payload: new Uint8Array([255]) }])).rejected,
      ).toHaveLength(1)
      expect(await left.records.adapter.get(entry)).toBeNull()
      expect(await left.records.listEntryCandidates({ ...source.address, keyVersion: 1 })).toEqual(
        [],
      )
    })

    test('projection SQL failure rolls back the record and candidate', async () => {
      const source = await chain(owner)
      await seed(source)
      await sql`alter table ${sql.table('vault_entries')} rename to vault_entries_gone`.execute(
        left.raw,
      )
      const entry = await dependent(owner, source, 'vault.entry')
      await expect(left.records.apply([entry])).rejects.toThrow()
      expect(await left.records.adapter.get(entry)).toBeNull()
      expect(await left.records.listEntryCandidates({ ...source.address, keyVersion: 1 })).toEqual(
        [],
      )
    })

    test.each(['vault.key', 'vault.wrapping', 'vault.entry'] as const)(
      '%s refuses mixed modes in both directions and after a signed tombstone',
      async (type) => {
        const source = await chain(owner)
        await seed(source)
        const record = type === 'vault.key' ? source.key : await dependent(owner, source, type)
        await left.records.apply([record])
        const row =
          type === 'vault.key'
            ? await left.store.getKey(source.address)
            : type === 'vault.entry'
              ? await left.store.getEntry({ ownerDID: owner.id, entryID: record.id })
              : await left.store.getWrapping({ ownerDID: owner.id, wrappingID: record.id })
        if (row === undefined) throw new Error('missing projection')
        const writeLocal = async () => {
          if (type === 'vault.key')
            await left.store.putKey({ ...source.address, suite: 1, version: 1, state: 'active' })
          else if (type === 'vault.entry')
            await left.store.putEntry(storedEntry(source.address, { entryID: record.id }))
          else {
            if ('wrappedKey' in row) await left.store.putWrapping(row)
          }
        }
        await expect(writeLocal()).rejects.toThrow(VaultModeConflict)
        const op = await verified(record)
        const deleted = await signed(owner, {
          ...op.claim,
          type,
          hlc: stamp(400),
          payload: null,
          meta:
            type === 'vault.key'
              ? { ...op.claim.meta, state: 'deleted' }
              : { ...op.claim.meta, ...(type === 'vault.entry' ? { contentHLC: stamp(300) } : {}) },
        })
        await left.records.apply([deleted])
        await expect(writeLocal()).rejects.toThrow(VaultModeConflict)
      },
    )

    test('rotation branch-set and entry CAS preconditions reject atomically', async () => {
      const source = await chain(owner)
      await seed(source)
      const entry = await dependent(owner, source, 'vault.entry')
      await left.records.apply([entry])
      const next = await chain(owner, { version: 2 })
      await expect(
        left.records.write({
          records: [next.key, next.branch],
          preconditions: { key: { ...source.address, expectedVersion: 1, expectedBranches: [] } },
        }),
      ).rejects.toThrow(VaultWriteConflict)
      const refreshed = await dependent(owner, source, 'vault.entry', {
        counter: 200,
        contentCounter: 190,
      })
      await expect(
        left.records.write({
          records: [refreshed],
          preconditions: {
            entry: { ownerDID: owner.id, entryID: entry.id, expectedHLC: stamp(0) },
          },
        }),
      ).rejects.toThrow(VaultWriteConflict)
      expect((await left.records.adapter.get(entry))?.copies).toEqual([entry])
      expect((await left.store.getKey(source.address))?.version).toBe(1)
    })

    test('reconciliation leaves include tombstones and change when a survivor copy is held', async () => {
      const source = await chain(owner)
      await seed(source)
      const before = await left.records.adapter.get(source.key)
      if (before === null) throw new Error('missing decision')
      const a = rangeLeaf(before, { kind: 'lww' })
      const copy = await resign(randomIdentity(), source.key)
      await left.records.apply([copy])
      const after = await left.records.adapter.get(source.key)
      if (after === null) throw new Error('missing decision')
      const b = rangeLeaf(after, { kind: 'lww' })
      expect(a).not.toEqual(b)
      expect(after.copies).toHaveLength(2)
    })

    test.each([
      ['vault.key', false],
      ['vault.key', true],
      ['vault.wrapping', false],
      ['vault.wrapping', true],
      ['vault.entry', false],
      ['vault.entry', true],
    ] as const)(
      '%s projection (deleted=%s) preserves a row predating optional registration and rolls back',
      async (type, deleted) => {
        const source = await chain(owner)
        const legacy = await openVaultTestDB(harness)
        const localKey = { ...source.address, suite: 1, version: 1, state: 'active' as const }
        const live = type === 'vault.key' ? source.key : await dependent(owner, source, type)
        const localEntry = storedEntry(source.address, { entryID: live.id })
        const wrapped = await getSuite(1).wrap({
          runtime: createRuntime(),
          contentKey: new Uint8Array(32),
          keyID: source.address.keyID,
          keyVersion: 1,
          wrappingID: live.id,
          factors: [{ kind: 'did', recipientDID: owner.id }],
        })
        const localWrapping = {
          ...source.address,
          ...wrapped,
          wrappingID: live.id,
          keyVersion: 1,
          recipientDID: owner.id,
          provenance: '',
        }
        if (type === 'vault.key') await legacy.store.putKey(localKey)
        else if (type === 'vault.entry') await legacy.store.putEntry(localEntry)
        else await legacy.store.putWrapping(localWrapping)

        legacy.db.register(vaultRecordsStoreDefinition)
        await getVaultRecordsStore(legacy.db, OP_KIND)
        const records = createVaultRecords({
          store: legacy.store,
          opKind: OP_KIND,
          authority,
          validateConsumerMetadata: metadata,
          nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
          maxDriftMS: 60_000,
        })
        peers.push({ ...legacy, records })
        const reservations = await sql`select * from ${sql.table('vault_decisions')}`.execute(
          legacy.raw,
        )
        expect(reservations.rows).toEqual([])
        if (type !== 'vault.key') {
          expect((await records.apply([source.key, source.branch])).applied).toBe(2)
        }
        const op = await verified(live)
        const record = deleted
          ? await signed(owner, {
              ...op.claim,
              type,
              hlc: stamp(300),
              payload: null,
              meta: {
                ...op.claim.meta,
                ...(type === 'vault.key' ? { state: 'deleted' } : {}),
                ...(type === 'vault.entry' ? { contentHLC: stamp(300) } : {}),
              },
            })
          : live
        const unrelated = await chain(randomIdentity())
        await expect(records.apply([unrelated.key, record])).rejects.toThrow(VaultModeConflict)
        expect(await records.adapter.get(record)).toBeNull()
        expect(await records.adapter.get(unrelated.key)).toBeNull()
        expect(await legacy.store.getKey(unrelated.address)).toBeUndefined()
        const claims =
          await sql`select * from ${sql.table('vault_decisions')} where owner = ${record.owner} and type = ${record.type} and id = ${record.id}`.execute(
            legacy.raw,
          )
        expect(claims.rows).toEqual([])
        if (type === 'vault.key')
          expect(await legacy.store.getKey(source.address)).toEqual(localKey)
        else if (type === 'vault.entry') {
          expect(await legacy.store.getEntry(localEntry)).toEqual(localEntry)
          expect(await records.listEntryCandidates({ ...source.address, keyVersion: 1 })).toEqual(
            [],
          )
        } else expect(await legacy.store.getWrapping(localWrapping)).toEqual(localWrapping)
      },
    )

    test('all local mutation verbs refuse replicated projections', async () => {
      const source = await chain(owner)
      await seed(source)
      const entry = await dependent(owner, source, 'vault.entry')
      const wrapping = await dependent(owner, source, 'vault.wrapping')
      await left.records.apply([entry, wrapping])
      const entryAddress = { ownerDID: owner.id, entryID: entry.id }
      const wrappingAddress = { ownerDID: owner.id, wrappingID: wrapping.id }
      const row = await left.store.getEntry(entryAddress)
      if (row === undefined) throw new Error('missing entry')
      for (const write of [
        () => left.store.setKeyState({ ...source.address, state: 'retired' }),
        () => left.store.setKeyVersion({ ...source.address, version: 2 }),
        () => left.store.deleteKey(source.address),
        () => left.store.updateEntryIfPresent(row),
        () => left.store.updateEntryIfUnchanged({ ...row, expectedHLC: row.hlc }),
        () =>
          left.store.moveEntry({
            ...row,
            keyID: createVaultKeyID(owner.id, new Uint8Array(16).fill(9)),
          }),
        () => left.store.deleteEntry(entryAddress),
        () => left.store.deleteWrapping(wrappingAddress),
        () => left.store.deleteWrappingsBelowVersion({ ...source.address, keyVersion: 2 }),
        // A replicated row anywhere in a batch refuses the batch.
        () => left.store.putEntries([storedEntry(source.address, { entryID: 'local-entry' }), row]),
        () => left.store.deleteEntries([entryAddress]),
        () => left.store.deleteWrappings([wrappingAddress]),
      ])
        await expect(write()).rejects.toThrow(VaultModeConflict)
      expect(await left.store.getEntry(entryAddress)).toEqual(row)
      expect(await left.records.listRevocations(source.address)).toEqual([])
      expect(await left.store.listWrappings(source.address)).toHaveLength(1)
    })

    test('operation kind is fixed for an adapter and its durable database', async () => {
      const source = await chain(owner)
      await seed(source)
      expect(() =>
        createVaultRecords({
          store: left.store,
          opKind: 'other/op',
          authority,
          validateConsumerMetadata: metadata,
          nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
          maxDriftMS: 60_000,
        }),
      ).toThrow(TypeError)
      await left.store.transaction(async (store) => {
        const other = createVaultRecords({
          store,
          opKind: 'other/op',
          authority,
          validateConsumerMetadata: metadata,
          nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
          maxDriftMS: 60_000,
        })
        await expect(other.adapter.transaction(async () => {})).rejects.toThrow(TypeError)
      })
    })

    test('initialisation binds the operation kind before the first apply without taking key locks', async () => {
      const rows = await sql<{
        op_kind: string
      }>`select op_kind from ${sql.table('vault_record_domain')}`.execute(left.raw)
      expect(rows.rows).toEqual([{ op_kind: OP_KIND }])
      expect(
        left.queries.some((query) =>
          /(?:pg_advisory_xact_lock|delete from.*vault_keys.*where 1 = 0)/i.test(query.sql),
        ),
      ).toBe(false)
      const start = left.queries.length
      await expect(getVaultRecordsStore(left.db, 'other/op')).rejects.toThrow(TypeError)
      expect(
        (
          await sql<{
            op_kind: string
          }>`select op_kind from ${sql.table('vault_record_domain')}`.execute(left.raw)
        ).rows,
      ).toEqual([{ op_kind: OP_KIND }])
      expect(
        left.queries
          .slice(start)
          .some((query) =>
            /(?:pg_advisory_xact_lock|delete from.*vault_keys.*where 1 = 0)/i.test(query.sql),
          ),
      ).toBe(false)
      await left.db.withTransaction(async (provider) => {
        await expect(getVaultRecordsStore(provider, OP_KIND)).rejects.toThrow(
          'outside caller transactions',
        )
      })
    })

    test('apply refuses an absent operation domain without binding it inside the transaction', async () => {
      await sql`delete from ${sql.table('vault_record_domain')}`.execute(left.raw)
      const source = await chain(owner)
      const start = left.queries.length
      await expect(left.records.apply([source.key])).rejects.toThrow('outside caller transactions')
      expect(
        (await sql`select * from ${sql.table('vault_record_domain')}`.execute(left.raw)).rows,
      ).toEqual([])
      expect(await left.store.getKey(source.address)).toBeUndefined()
      expect(
        left.queries
          .slice(start)
          .some((query) => /insert into.*vault_record_domain/i.test(query.sql)),
      ).toBe(false)
    })

    test('copy pruning never removes the last surviving signer and updates range fingerprints', async () => {
      const source = await chain(owner)
      await seed(source)
      const old = await left.records.adapter.get(source.key)
      if (old === null) throw new Error('missing decision')
      const originalLeaf = rangeLeaf(old, { kind: 'lww' })
      await left.records.adapter.transaction(async (tx) => {
        await tx.pruneCopy(source.key, owner.id)
      })
      expect((await left.records.adapter.get(source.key))?.copies).toHaveLength(1)
      const survivor = randomIdentity()
      const copy = await resign(survivor, source.key)
      await left.records.apply([copy])
      await left.records.adapter.transaction(async (tx) => {
        await tx.pruneCopy(source.key, owner.id)
      })
      const current = await left.records.adapter.get(source.key)
      if (current === null) throw new Error('missing decision')
      expect(current.copies).toEqual([copy])
      const currentLeaf = rangeLeaf(current, { kind: 'lww' })
      if (currentLeaf === null || originalLeaf === null) throw new Error('missing range leaf')
      expect(fingerprintRange([currentLeaf])).not.toEqual(fingerprintRange([originalLeaf]))
      expect((await left.store.getKey(source.address))?.version).toBe(1)
    })

    test('first-use applies never write the operation domain while a vault key lock is held', async () => {
      const source = await chain(owner)
      const next = await chain(owner, { version: 2 })
      const create = (store: VaultRecordsParams['store']) =>
        createVaultRecords({
          store,
          opKind: OP_KIND,
          authority,
          validateConsumerMetadata: metadata,
          nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
          maxDriftMS: 60_000,
        })
      const start = left.queries.length
      let contender: Promise<unknown> | undefined
      await left.db
        .withTransaction(async (provider) => {
          await withKeyLock(
            provider,
            'vault_keys',
            [JSON.stringify([owner.id, source.address.keyID])],
            async (locked) => {
              const store = await getVaultStore(locked)
              if (left.kind === 'postgres') {
                vi.mocked(withKeyLocks).mockClear()
                contender = left.records.apply([next.key])
                // Observe rejection immediately while the holder is still running.
                void contender.catch(() => {})
                await vi.waitFor(() => expect(withKeyLocks).toHaveBeenCalled())
              }
              const result = await create(store).apply([source.key])
              expect(result.rejected).toEqual([])
              expect(result.applied).toBe(1)
              const writes = left.queries
                .slice(start)
                .filter((query) =>
                  /(?:insert into|update|delete from).*vault_record_domain/i.test(query.sql),
                )
              expect(writes, 'domain binding must commit before any vault key lock').toEqual([])
            },
          )
        })
        .finally(async () => {
          await contender
        })
      if (left.kind !== 'postgres') {
        // SQLite serialises independent transactions. Check both first-use writes' SQL contract.
        expect((await left.records.apply([next.key])).applied).toBe(1)
      }
      expect(
        left.queries
          .slice(start)
          .filter((query) =>
            /(?:insert into|update|delete from).*vault_record_domain/i.test(query.sql),
          ),
      ).toEqual([])
      expect((await left.store.getKey(source.address))?.version).toBe(2)
    })

    test('concurrent replicated applies in one caller transaction hold the key lock through authority and persistence', async () => {
      const source = await chain(owner)
      await seed(source)
      const two = await chain(owner, { version: 2 })
      const three = await chain(owner, { version: 3 })
      await left.store.transaction(async (store) => {
        const entered = Promise.withResolvers<void>()
        const release = Promise.withResolvers<void>()
        let secondEntered = false
        const records = createVaultRecords({
          store,
          opKind: OP_KIND,
          validateConsumerMetadata: metadata,
          nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
          maxDriftMS: 60_000,
          authority: {
            async authorize(request) {
              if (request.op.claim.meta.version === 2) {
                entered.resolve()
                await release.promise
              }
              if (request.op.claim.meta.version === 3) secondEntered = true
              return true
            },
          },
        })
        const first = records.apply([two.key])
        await entered.promise
        const second = records.apply([three.key])
        try {
          await new Promise((resolve) => setTimeout(resolve, 40))
          expect(
            secondEntered,
            'second apply must wait for the complete first critical section',
          ).toBe(false)
        } finally {
          release.resolve()
          await Promise.all([first, second])
        }
      })
      expect((await left.store.getKey(source.address))?.version).toBe(3)
    })

    test('revocation suppresses an existing wrapping whose factor uses a long-form peer DID', async () => {
      const source = await chain(owner)
      await seed(source)
      const identity = await createIdentity({
        keys: [
          { purpose: 'sig', alg: 'EdDSA' },
          { purpose: 'kem', alg: 'X25519' },
        ],
      })
      const wrapping = await dependent(owner, source, 'vault.wrapping', {
        recipient: null,
        factorRecipient: identity.longForm,
      })
      expect((await right.records.apply([wrapping])).rejected).toEqual([])
      expect(await right.store.listWrappings(source.address)).toHaveLength(1)
      const recipient = normalizeDID(identity.longForm)
      const revocation = await signed(owner, {
        type: 'vault.revocation',
        id: vaultRevocationRecordID(source.address.keyID, recipient),
        owner: owner.id,
        hlc: stamp(200),
        payload: encodeVaultRecordPayload('vault.revocation', {}),
        meta: { keyID: source.address.keyID, revokedDID: recipient, consumer: {} },
      })
      expect((await right.records.apply([revocation])).rejected).toEqual([])
      expect(await right.store.listWrappings(source.address)).toEqual([])
      expect(
        (
          await right.records.apply([
            await dependent(owner, source, 'vault.wrapping', {
              counter: 300,
              recipient: null,
              factorRecipient: identity.longForm,
            }),
          ])
        ).rejected.map((r) => r.reason),
      ).toEqual(['unauthorized'])
    })

    test('signed writes require a precondition covering every output address', async () => {
      const source = await chain(owner)
      await seed(source)
      const next = await chain(owner, { version: 2 })
      await expect(left.records.write({ records: [next.key], preconditions: {} })).rejects.toThrow(
        TypeError,
      )
      const unrelated = await chain(randomIdentity())
      await expect(
        left.records.write({
          records: [unrelated.key],
          preconditions: { key: { ...source.address, expectedVersion: 1 } },
        }),
      ).rejects.toThrow(TypeError)
      expect(await left.records.adapter.get(unrelated.key)).toBeNull()
      expect((await left.store.getKey(source.address))?.version).toBe(1)
    })

    test('reads refuse another durable operation domain even for an empty type list', async () => {
      const source = await chain(owner)
      await seed(source)
      await left.store.transaction(async (store) => {
        const other = createVaultRecords({
          store,
          opKind: 'other/op',
          authority,
          validateConsumerMetadata: metadata,
          nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
          maxDriftMS: 60_000,
        })
        await expect(other.adapter.list([])).rejects.toThrow(TypeError)
        await expect(other.adapter.get(source.key)).rejects.toThrow(TypeError)
        await expect(other.adapter.getMany?.([])).rejects.toThrow(TypeError)
        await expect(other.listRevocations(source.address)).rejects.toThrow(TypeError)
      })
    })

    test('corrupt listing reports one bad decision without hiding good records', async () => {
      const source = await chain(owner)
      await seed(source)
      const good = await dependent(owner, source, 'vault.entry', { id: 'good' })
      const bad = await dependent(owner, source, 'vault.entry', { id: 'bad' })
      await left.records.apply([good, bad])
      await sql`update ${sql.table('vault_records')} set deleted = 7 where id = ${bad.id}`.execute(
        left.raw,
      )
      const errors: Array<{ type: string; id: string; error: unknown }> = []
      const records = createVaultRecords({
        store: left.store,
        opKind: OP_KIND,
        authority,
        validateConsumerMetadata: metadata,
        nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
        maxDriftMS: 60_000,
        onCorruptRow: (error) => errors.push(error),
      })
      expect(
        (await records.adapter.list(['vault.entry'])).flatMap((decision) => decision.copies),
      ).toEqual([good])
      expect(errors).toHaveLength(1)
      expect(errors[0]).toMatchObject({
        type: 'vault.entry',
        id: 'bad',
        error: expect.any(VaultRecordRowError),
      })
    })

    test('invalid stored signature is excluded beside a valid copy and pruned on the next endorsement', async () => {
      const source = await chain(owner)
      await seed(source)
      const second = await resign(randomIdentity(), source.key)
      await left.records.apply([second])
      await sql`update ${sql.table('vault_records')} set op_jwt = ${'invalid-signature'} where op_hash = ${second.opHash}`.execute(
        left.raw,
      )
      expect((await left.records.adapter.get(source.key))?.copies).toEqual([source.key])
      const third = await resign(randomIdentity(), source.key)
      await left.records.apply([third])
      expect(
        (await left.records.adapter.get(source.key))?.copies.map((r) => r.opHash).sort(),
      ).toEqual([source.key.opHash, third.opHash].sort())
      const rows = await sql<{
        op_hash: string
      }>`select op_hash from ${sql.table('vault_records')} where type = ${source.key.type} and owner = ${source.key.owner} and id = ${source.key.id}`.execute(
        left.raw,
      )
      expect(rows.rows.map((row) => row.op_hash).sort()).toEqual(
        [source.key.opHash, third.opHash].sort(),
      )
    })

    test('replicated reads perform no writes and expose signed standard columns', async () => {
      const source = await chain(owner)
      await seed(source)
      const entry = await dependent(owner, source, 'vault.entry')
      await left.records.apply([entry])
      const start = left.queries.length
      await left.records.adapter.get(entry)
      await left.records.adapter.getMany?.([entry, source.key])
      await left.records.adapter.list(TYPES)
      await left.records.listKeyBranches({ ...source.address, keyVersion: 1 })
      await left.records.listEntryCandidates({ ...source.address, keyVersion: 1 })
      await left.records.listPriorEntryTombstones({ ...source.address, beforeVersion: 2 })
      await left.records.listRevocations(source.address)
      expect(left.queries.slice(start).every((q) => /^\s*(select|begin|commit)/i.test(q.sql))).toBe(
        true,
      )
      const result = await sql<{
        deleted: number
        payload_digest: string
        hlc: string
        op_jwt: string
        op_hash: string
      }>`select deleted, payload_digest, hlc, op_jwt, op_hash from ${sql.table('vault_records')} where id = ${entry.id}`.execute(
        left.raw,
      )
      expect(result.rows).toEqual([
        {
          deleted: 0,
          payload_digest: recordPayloadDigest(entry.payload),
          hlc: entry.hlc,
          op_jwt: entry.opJWT,
          op_hash: entry.opHash,
        },
      ])
    })

    test('two signed writes sharing one caller transaction check CAS inside the held key lock', async () => {
      const source = await chain(owner)
      await seed(source)
      const two = await chain(owner, { version: 2 })
      const three = await chain(owner, { version: 3 })
      await left.store.transaction(async (store) => {
        const records = createVaultRecords({
          store,
          opKind: OP_KIND,
          authority,
          validateConsumerMetadata: metadata,
          nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
          maxDriftMS: 60_000,
        })
        const results = await Promise.allSettled(
          [two, three].map((next) =>
            records.write({
              records: [next.key],
              preconditions: {
                key: { ...source.address, expectedVersion: 1, expectedBranches: [source.branchID] },
              },
            }),
          ),
        )
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
        const refused = results.find((r) => r.status === 'rejected')
        expect(refused?.status === 'rejected' ? refused.reason : undefined).toBeInstanceOf(
          VaultWriteConflict,
        )
      })
      expect([2, 3]).toContain((await left.store.getKey(source.address))?.version)
    })

    test('noncanonical signed envelopes are refused and excluded beside valid stored copies', async () => {
      const source = await chain(owner)
      await seed(source)
      const op = await verified(source.key)
      const opJWT = stringifyToken(
        await owner.signToken({
          kind: OP_KIND,
          claim: toB64U(canonicalRecordClaim(op.claim)),
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      )
      const opHash = toB64U(blake3(fromUTF(`${opJWT.length}:${opJWT}`), { dkLen: 32 }))
      const malformed = { ...source.key, opJWT, opHash }
      expect((await left.records.apply([malformed])).rejected.map((r) => r.reason)).toEqual([
        'signature',
      ])
      await sql`insert into ${sql.table('vault_records')} (type, owner, id, hlc, op_jwt, op_hash, payload, payload_digest, deleted, meta)
        select type, owner, id, hlc, ${opJWT}, ${opHash}, payload, payload_digest, deleted, meta from ${sql.table('vault_records')} where op_hash = ${source.key.opHash}`.execute(
        left.raw,
      )
      expect((await left.records.adapter.get(source.key))?.copies).toEqual([source.key])
      expect((await left.records.adapter.list(['vault.key'])).flatMap((d) => d.copies)).toEqual([
        source.key,
      ])
    })

    test('a first entry tombstone remains signed and prevents stale resurrection', async () => {
      const source = await chain(owner)
      await seed(source)
      const deleted = await dependent(owner, source, 'vault.entry', {
        deleted: true,
        counter: 200,
        contentCounter: 190,
      })
      expect((await left.records.apply([deleted])).applied).toBe(1)
      const stale = await dependent(owner, source, 'vault.entry', {
        counter: 300,
        contentCounter: 100,
      })
      expect((await left.records.apply([stale])).applied).toBe(0)
      expect((await left.records.adapter.get(deleted))?.copies).toEqual([deleted])
      expect(await left.store.getEntry({ ownerDID: owner.id, entryID: deleted.id })).toBeUndefined()
      expect((await exchange(left.records.adapter, right.records)).rejected).toEqual([])
      expect((await right.records.adapter.get(deleted))?.copies).toEqual([deleted])
    })

    test('key versions and retirement outrank later operation clocks on both engines', async () => {
      const two = await chain(owner, { version: 2 })
      await seed(two)
      const older = await chain(owner, { version: 1, counter: 300 })
      expect((await right.records.apply([older.key])).applied).toBe(0)
      const retired = await chain(owner, { version: 2, state: 'retired', counter: 30 })
      await right.records.apply([retired.key])
      const active = await chain(owner, { version: 2, counter: 400 })
      await right.records.apply([active.key])
      await exchange(right.records.adapter, left.records)
      for (const current of [left, right]) {
        expect(await current.store.getKey(two.address)).toMatchObject({
          version: 2,
          state: 'retired',
        })
      }
    })

    test('a key tombstone outranks activation at the same version and remains a signed decision', async () => {
      const source = await chain(owner)
      await seed(source)
      const op = await verified(source.key)
      const deleted = await signed(owner, {
        ...op.claim,
        type: 'vault.key',
        hlc: stamp(5),
        payload: null,
        meta: { ...op.claim.meta, state: 'deleted' },
      })
      expect((await right.records.apply([deleted])).applied).toBe(1)
      const later = await chain(owner, { counter: 300 })
      expect((await right.records.apply([later.key])).applied).toBe(0)
      await exchange(right.records.adapter, left.records)
      for (const current of [left, right]) {
        expect(await current.store.getKey(source.address)).toBeUndefined()
        expect((await current.records.adapter.get(deleted))?.copies[0]?.payload).toBeNull()
      }
    })

    test('wrapping LWW selects the later operation and ignores its replayed predecessor', async () => {
      const source = await chain(owner)
      await seed(source)
      const first = await dependent(owner, source, 'vault.wrapping', { counter: 100 })
      const next = await dependent(owner, source, 'vault.wrapping', { counter: 120 })
      await left.records.apply([first])
      await exchange(left.records.adapter, right.records)
      expect((await right.records.apply([next])).applied).toBe(1)
      expect((await right.records.apply([first])).applied).toBe(0)
      await exchange(right.records.adapter, left.records)
      for (const current of [left, right]) {
        expect((await current.records.adapter.get(next))?.copies[0]?.opHash).toBe(next.opHash)
      }
    })

    test('entry content intent orders before key version, which breaks equal-content-stamp ties', async () => {
      const one = await chain(owner)
      await seed(one)
      const original = await dependent(owner, one, 'vault.entry', {
        counter: 100,
        contentCounter: 90,
      })
      await left.records.apply([original])
      await exchange(left.records.adapter, right.records)
      const two = await chain(owner, { version: 2 })
      const refreshed = await dependent(owner, two, 'vault.entry', {
        counter: 200,
        contentCounter: 90,
      })
      await right.records.apply([two.key, two.branch, refreshed])
      await exchange(right.records.adapter, left.records)
      expect((await left.records.adapter.get(original))?.copies[0]?.opHash).toBe(refreshed.opHash)
      const newerContent = await dependent(owner, one, 'vault.entry', {
        counter: 300,
        contentCounter: 100,
      })
      await left.records.apply([newerContent])
      await exchange(left.records.adapter, right.records)
      for (const current of [left, right]) {
        expect((await current.records.adapter.get(original))?.copies[0]?.opHash).toBe(
          newerContent.opHash,
        )
      }
    })

    test.each(['vault.wrapping', 'vault.entry'] as const)(
      '%s waits for its exact owner, version and branch proof',
      async (type) => {
        const exact = await chain(owner)
        const other = await chain(owner, { counter: 11 })
        await left.records.apply([exact.key, exact.branch])
        await right.records.apply([other.key, other.branch])
        const record = await dependent(owner, exact, type)
        expect((await right.records.apply([record])).parked).toEqual([record])
        expect(await right.records.adapter.get(record)).toBeNull()
        const result = await right.records.apply([exact.branch, record])
        expect(result.rejected).toEqual([])
        expect(result.parked).toEqual([])
        expect(result.applied).toBe(2)
        const copies = (await right.records.adapter.get(record))?.copies
        expect(copies?.[0]?.payload).toEqual(record.payload)
        const op = await verified(record)
        const wrongVersion = await signed(owner, {
          ...op.claim,
          payload: record.payload,
          type,
          meta: { ...op.claim.meta, keyVersion: 2 },
        })
        expect((await right.records.apply([wrongVersion])).parked).toEqual([wrongVersion])
        const anotherOwner = randomIdentity()
        const foreign = await signed(anotherOwner, {
          ...op.claim,
          payload: record.payload,
          type,
          owner: anotherOwner.id,
        })
        expect((await right.records.apply([foreign])).parked).toEqual([foreign])
      },
    )

    test('forks retain both branches and choose claim digest before op hash in either order', async () => {
      let pair: { winner: Chain; loser: Chain } | undefined
      for (let counter = 20; counter < 148; counter += 2) {
        const first = await chain(owner, { version: 2, counter })
        const second = await chain(owner, { version: 2, counter: counter + 1 })
        const firstDigest = await recordDecisionDigest(first.key, OP_KIND)
        const secondDigest = await recordDecisionDigest(second.key, OP_KIND)
        if (firstDigest === secondDigest) continue
        const [winner, loser] = firstDigest > secondDigest ? [first, second] : [second, first]
        if (winner.key.opHash < loser.key.opHash) {
          pair = { winner, loser }
          break
        }
      }
      if (pair === undefined) throw new Error('no opposing digest/op-hash fixture in 64 attempts')
      const { winner, loser } = pair
      for (const [current, order] of [
        [left, [winner, loser]],
        [right, [loser, winner]],
      ] as const) {
        const result = await current.records.apply(order.flatMap((item) => [item.key, item.branch]))
        expect(result.rejected).toEqual([])
        expect(result.conflicts.some((conflict) => conflict.forked)).toBe(true)
        const head = await current.records.adapter.get(winner.key)
        expect(head?.copies[0]?.opHash).toBe(winner.key.opHash)
        const branches = await current.records.listKeyBranches({ ...winner.address, keyVersion: 2 })
        expect(branches.map((branch) => branch.branchID).sort()).toEqual(
          [winner.branchID, loser.branchID].sort(),
        )
        expect(selectWinningBranch(branches.map((branch) => branch.introducingOp)).opHash).toBe(
          winner.key.opHash,
        )
      }
      await exchange(left.records.adapter, right.records)
      await exchange(right.records.adapter, left.records)
      expect((await left.records.adapter.get(winner.key))?.contentDigest).toBe(
        (await right.records.adapter.get(winner.key))?.contentDigest,
      )
    })

    test('equal-claim branches use op hash as their sole remaining tie-break', async () => {
      const original = await chain(owner)
      const otherCopy = await resign(randomIdentity(), original.key)
      const ops = [await verified(original.key), await verified(otherCopy)] as const
      expect(recordClaimDigest(ops[0].claim)).toBe(recordClaimDigest(ops[1].claim))
      expect(ops[0].opHash).not.toBe(ops[1].opHash)
      const expected = [original.key.opHash, otherCopy.opHash].sort().at(-1)
      expect(selectWinningBranch(ops).opHash).toBe(expected)
      expect(selectWinningBranch([...ops].reverse()).opHash).toBe(expected)
    })

    test('authorised losing entries remain received candidates while refused entries do not', async () => {
      const source = await chain(owner)
      await seed(source)
      const winner = await dependent(owner, source, 'vault.entry', {
        counter: 110,
        contentCounter: 100,
      })
      const loser = await dependent(owner, source, 'vault.entry', {
        counter: 120,
        contentCounter: 90,
      })
      await left.records.apply([winner])
      await exchange(left.records.adapter, right.records)
      await right.records.apply([loser])
      expect((await right.records.adapter.get(winner))?.copies[0]?.opHash).toBe(winner.opHash)
      expect(
        (await right.records.listEntryCandidates({ ...source.address, keyVersion: 1 }))
          .map((record) => record.opHash)
          .sort(),
      ).toEqual([winner.opHash, loser.opHash].sort())
      const refused = await dependent(randomIdentity(), source, 'vault.entry', {
        counter: 130,
        contentCounter: 120,
      })
      vi.mocked(authority.authorize).mockImplementation(
        async (request) => request.issuer === owner.id,
      )
      expect((await right.records.apply([refused])).rejected.map((item) => item.reason)).toEqual([
        'unauthorized',
      ])
      expect(
        (await right.records.listEntryCandidates({ ...source.address, keyVersion: 1 })).some(
          (record) => record.opHash === refused.opHash,
        ),
      ).toBe(false)
      expect(
        (await left.records.listEntryCandidates({ ...source.address, keyVersion: 1 })).some(
          (record) => record.opHash === loser.opHash,
        ),
      ).toBe(false)
    })

    test('prior tombstones survive version changes and defeat older content re-encryption', async () => {
      const one = await chain(owner)
      await seed(one)
      const deleted = await dependent(owner, one, 'vault.entry', {
        deleted: true,
        counter: 100,
        contentCounter: 95,
      })
      await left.records.apply([deleted])
      await exchange(left.records.adapter, right.records)
      const two = await chain(owner, { version: 2 })
      await right.records.apply([two.key, two.branch])
      const stale = await dependent(owner, two, 'vault.entry', { counter: 200, contentCounter: 90 })
      await right.records.apply([stale])
      expect((await right.records.adapter.get(deleted))?.copies[0]?.payload).toBeNull()
      expect(await right.store.getEntry({ ...one.address, entryID: deleted.id })).toBeUndefined()
      expect(
        (await right.records.listPriorEntryTombstones({ ...one.address, beforeVersion: 2 })).map(
          (record) => record.opHash,
        ),
      ).toContain(deleted.opHash)
    })

    test.each(['recipient', 'factor'] as const)(
      'revocation permanently suppresses regrant through the %s address',
      async (field) => {
        const source = await chain(owner)
        await seed(source)
        const recipient = randomIdentity()
        const wrapping = await dependent(owner, source, 'vault.wrapping', {
          recipient: field === 'recipient' ? recipient.id : null,
          factorRecipient: field === 'recipient' ? owner.id : recipient.id,
        })
        await right.records.apply([wrapping])
        const next = await chain(owner, { version: 2 })
        const nextWrapping = await dependent(owner, next, 'vault.wrapping', {
          id: 'newer-wrapping',
          recipient: field === 'recipient' ? recipient.id : null,
          factorRecipient: field === 'recipient' ? owner.id : recipient.id,
        })
        await right.records.apply([next.key, next.branch, nextWrapping])
        expect(await right.store.listWrappings(source.address)).toHaveLength(2)
        const revocation = await signed(owner, {
          type: 'vault.revocation',
          id: vaultRevocationRecordID(source.address.keyID, recipient.id),
          owner: owner.id,
          hlc: stamp(200),
          payload: encodeVaultRecordPayload('vault.revocation', {}),
          meta: { keyID: source.address.keyID, revokedDID: recipient.id, consumer: {} },
        })
        await left.records.apply([revocation])
        await exchange(left.records.adapter, right.records)
        expect(await right.records.listRevocations(source.address)).toEqual([recipient.id])
        expect(await right.store.listWrappings(source.address)).toEqual([])
        const later = await dependent(owner, next, 'vault.wrapping', {
          counter: 300,
          recipient: field === 'recipient' ? recipient.id : null,
          factorRecipient: field === 'recipient' ? owner.id : recipient.id,
        })
        expect((await right.records.apply([later])).rejected.map((item) => item.reason)).toEqual([
          'unauthorized',
        ])
        const op = await verified(revocation)
        const unrevocation = await signed(owner, {
          ...op.claim,
          type: 'vault.revocation',
          hlc: stamp(400),
          payload: null,
        })
        expect(
          (await right.records.apply([unrevocation])).rejected.map((item) => item.reason),
        ).toEqual(['unauthorized'])
        expect(await right.records.listRevocations(source.address)).toEqual([recipient.id])
      },
    )

    test('entry mode is checked independently at its owner-qualified address', async () => {
      const source = await chain(owner)
      await seed(source)
      const row = storedEntry(source.address, { entryID: 'shared-entry' })
      await right.store.putEntry(row)
      const entry = await dependent(owner, source, 'vault.entry')
      await expect(right.records.apply([entry])).rejects.toThrow(VaultModeConflict)
      expect(await right.store.getEntry(row)).toEqual(row)
      expect(await right.records.adapter.get(entry)).toBeNull()
    })

    test('signed local output enters apply and cannot bypass authority or write preconditions', async () => {
      const source = await chain(owner)
      await seed(source)
      const next = await chain(owner, { version: 2 })
      expect(left.records).not.toHaveProperty('putRecord')
      const result = await left.records.write({
        records: [next.key, next.branch],
        preconditions: {
          key: { ...source.address, expectedVersion: 1, expectedBranches: [source.branchID] },
        },
      })
      expect(result.rejected).toEqual([])
      expect((await left.records.adapter.get(next.key))?.copies).toEqual([next.key])
      const third = await chain(owner, { version: 3 })
      await expect(
        left.records.write({
          records: [third.key],
          preconditions: { key: { ...source.address, expectedVersion: 1 } },
        }),
      ).rejects.toThrow(VaultWriteConflict)
      vi.mocked(authority.authorize).mockResolvedValue(false)
      const refused = await left.records.write({
        records: [third.key],
        preconditions: { key: { ...source.address, expectedVersion: 2 } },
      })
      expect(refused.rejected.map((item) => item.reason)).toEqual(['unauthorized'])
      expect(await left.store.getKey(source.address)).toMatchObject({ version: 2 })
    })

    test('authority receives verified fields and the identical transport object, and refusal blocks apply', async () => {
      const transportContext = {
        requester: randomIdentity().id,
        evidence: new Map([['channel', 'local']]),
      }
      const source = await chain(owner, { consumer: { opaque: ['consumer-owned', 7] } })
      vi.mocked(authority.authorize).mockImplementation(async (request) => {
        if (request.source !== 'record')
          throw new Error('receipt requires a verified record request')
        expect(request.transportContext).toBe(transportContext)
        expect(request.owner).toBe(source.key.owner)
        expect(request.issuer).toBe(owner.id)
        expect(request.verb).toBe('administer')
        expect(request.recordKey).toEqual({
          type: source.key.type,
          owner: source.key.owner,
          id: source.key.id,
        })
        expect(request.record.opJWT).toBe(source.key.opJWT)
        expect(request.store).not.toBe(right.records.adapter)
        return false
      })
      const result = await right.records.apply([source.key], transportContext)
      expect(result.rejected.map((item) => item.reason)).toEqual(['unauthorized'])
      expect(authority.authorize).toHaveBeenCalledTimes(1)
      expect(await right.records.adapter.get(source.key)).toBeNull()
      expect(await right.store.getKey(source.address)).toBeUndefined()
      expect((await verified(source.key)).claim.meta).not.toHaveProperty('transportContext')
    })

    test('a refused signed consumer extension blocks admission without a fallback', async () => {
      const source = await chain(owner, { consumer: { opaque: 'unsupported-evidence' } })
      metadata.mockResolvedValueOnce(false)
      const result = await right.records.apply([source.key])
      expect(metadata).toHaveBeenCalledWith(
        { opaque: 'unsupported-evidence' },
        expect.objectContaining({ issuer: owner.id }),
      )
      expect(result.rejected.map((item) => item.reason)).toEqual(['unauthorized'])
      expect(await right.store.getKey(source.address)).toBeUndefined()
    })

    test('an operation signed under another explicit kind is refused', async () => {
      const source = await chain(owner)
      const op = await verified(source.key)
      const foreign = {
        ...source.key,
        ...(await signRecordOp(owner, op.claim, 'other/record-op/v1')),
      }
      expect((await right.records.apply([foreign])).rejected.map((item) => item.reason)).toEqual([
        'signature',
      ])
      expect(await right.records.adapter.get(source.key)).toBeNull()
    })

    test('removed signer copies refuse new receipt while an effective member re-endorses identical content', async () => {
      const survivor = randomIdentity()
      const origin = randomIdentity()
      const incarnations = {
        [origin.id]: { add: toB64U(new Uint8Array(32).fill(1)), g: 0 },
        [survivor.id]: { add: toB64U(new Uint8Array(32).fill(2)), g: 0 },
      }
      let removed = false
      const resolveMemberHistoric = vi.fn(
        async (did: string, query: { add: string; gen: number }) => {
          const incarnation = incarnations[did]
          if (
            incarnation === undefined ||
            query.add !== incarnation.add ||
            query.gen !== incarnation.g
          ) {
            throw new Error('incarnation outside the current generation')
          }
          return {
            key: {
              alg: 'EdDSA' as const,
              publicKey: did === origin.id ? origin.publicKey : survivor.publicKey,
            },
            lease: null,
            removed: did === origin.id && removed,
          }
        },
      )
      const historicAuthority: CredentialAuthority = {
        async authorize(request: CredentialAuthorityRequest) {
          if (request.source !== 'record') return false
          const consumer = request.op.claim.meta.consumer as { incarnations: typeof incarnations }
          const member = consumer.incarnations[request.issuer]
          if (member === undefined) return false
          const historic = await resolveMemberHistoric(request.issuer, {
            add: member.add,
            gen: member.g,
          })
          if (historic.removed) return false
          const [header, body, signature] = request.record.opJWT.split('.')
          if (header === undefined || body === undefined || signature === undefined) return false
          return ed25519.verify(
            fromB64U(signature),
            fromUTF(`${header}.${body}`),
            historic.key.publicKey,
          )
        },
      }
      const sender = await peer(historicAuthority)
      const receiver = await peer(historicAuthority)
      const source = await chain(origin, { owner: owner.id, consumer: { incarnations } })
      expect((await sender.records.apply([source.key])).applied).toBe(1)
      removed = true
      const refused = await exchange(sender.records.adapter, receiver.records)
      expect(refused.rejected.map((item) => item.reason)).toEqual(['unauthorized'])
      expect(await receiver.records.adapter.get(source.key)).toBeNull()
      const copy = await resign(survivor, source.key)
      expect(copy.payload).toEqual(source.key.payload)
      expect(copy.hlc).toBe(source.key.hlc)
      expect(copy.opHash).not.toBe(source.key.opHash)
      expect(await recordDecisionDigest(copy, OP_KIND)).toBe(
        await recordDecisionDigest(source.key, OP_KIND),
      )
      expect(
        (
          await sender.records.write({
            records: [copy],
            preconditions: { key: { ...source.address, expectedVersion: 1 } },
          })
        ).rejected,
      ).toEqual([])
      expect((await exchange(sender.records.adapter, receiver.records)).rejected).toEqual([])
      expect(
        (await receiver.records.adapter.get(copy))?.copies.map((record) => record.opHash),
      ).toEqual([copy.opHash])
      expect(resolveMemberHistoric).toHaveBeenCalledWith(origin.id, {
        add: incarnations[origin.id]?.add,
        gen: 0,
      })
      expect(resolveMemberHistoric).toHaveBeenCalledWith(survivor.id, {
        add: incarnations[survivor.id]?.add,
        gen: 0,
      })
    })
  })
}
