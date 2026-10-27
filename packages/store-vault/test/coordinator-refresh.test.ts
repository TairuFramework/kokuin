import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import type { SignedRecord } from '@kokuin/records'
import { verifySignedRecord } from '@kokuin/records'
import { randomIdentity } from '@kokuin/token'
import { selectWinningBranch, VAULT_OP_KIND } from '@kokuin/vault'
import { createRuntime } from '@sozai/runtime'
import { afterEach, describe, expect, test } from 'vitest'

import type { VaultCoordinatorParams } from '../src/index.js'
import { createVaultCoordinator, createVaultRecords, getVaultStore } from '../src/index.js'
import { openVaultTestDB, stamp } from './cases.js'

const bytes = (value: string) => new TextEncoder().encode(value)
const metadata = { kind: 'blob', label: 'Grant', attributes: { device: 'self' } }
const types = ['vault.key', 'vault.key-branch', 'vault.wrapping', 'vault.entry', 'vault.revocation']
let counter = 1000
// Two full repair exchanges across every survivor exceed the default 5 s on CI runners.
const REPAIR_EXCHANGE_TIMEOUT = 30_000

const databases: Array<Awaited<ReturnType<typeof openVaultTestDB>>> = []
async function fixture(identity = randomIdentity()) {
  const db = await openVaultTestDB(
    {
      name: 'SQLite',
      createAdapter: async () => new NodeSQLiteAdapter({ database: ':memory:' }),
      cleanup: async () => {},
    },
    true,
  )
  databases.push(db)
  const params: VaultCoordinatorParams = {
    mode: 'replicated',
    store: db.store,
    identity,
    signer: identity,
    principal: identity.id,
    runtime: createRuntime(),
    authority: { authorize: async () => true },
    nextHLC: async () => stamp(++counter),
    records: {
      opKind: VAULT_OP_KIND,
      nowMS: () => Date.parse('2026-10-01T01:00:00.000Z'),
      maxDriftMS: 60_000,
      validateConsumerMetadata: async () => true,
    },
  }
  return { ...db, params, identity, manager: createVaultCoordinator(params) }
}
type Fixture = Awaited<ReturnType<typeof fixture>>
async function copies(f: Fixture): Promise<Array<SignedRecord>> {
  return (await f.manager.records.adapter.list(types)).flatMap((d) => d.copies)
}
async function selected(f: Fixture, type: string, owner: string, id: string) {
  const record = (await f.manager.records.adapter.get({ type, owner, id }))?.copies[0]
  if (!record) throw new Error('Missing record')
  return record
}
function marker(value: unknown): string | undefined {
  if (
    value !== null &&
    typeof value === 'object' &&
    'repair' in value &&
    typeof value.repair === 'string'
  )
    return value.repair
  return undefined
}
async function injectAtClock(
  f: Fixture,
  injected: Array<SignedRecord>,
  action: (manager: ReturnType<typeof createVaultCoordinator>) => Promise<unknown>,
) {
  return f.db.withTransaction(async (provider) => {
    const store = await getVaultStore(provider)
    if (f.params.mode !== 'replicated') throw new Error('Expected replicated fixture')
    const records = createVaultRecords({
      ...f.params.records,
      authority: f.params.authority,
      store,
    })
    let once = true
    const manager = createVaultCoordinator({
      ...f.params,
      store,
      nextHLC: async () => {
        if (once) {
          once = false
          await records.adapter.transaction(async (tx) => {
            for (const record of injected) await tx.putCopy(record)
          })
        }
        return stamp(++counter)
      },
    })
    return action(manager)
  })
}
afterEach(async () => {
  for (const db of databases.splice(0)) await db.db.close()
})

describe('SQLite coordinator refresh', () => {
  test('refreshEntry preserves authenticated intent and public metadata at the current version', async () => {
    const f = await fixture()
    const key = await f.manager.createKey({ ownerDID: f.identity.id })
    const entry = await f.manager.putEntry({
      ...key,
      entryID: 'grant',
      plaintext: bytes('token'),
      ...metadata,
    })
    const before = await selected(f, 'vault.entry', key.ownerDID, entry.entryID)
    const row = await f.store.getEntry(entry)
    if (!row) throw new Error('Missing entry')
    await f.manager.rotate({
      ...key,
      excludedRecipients: [],
      reissue: [{ ...entry, action: 'skip' }],
    })
    expect(
      await f.manager.refreshEntry({ ...entry, expectedHLC: row.hlc, consumer: { current: true } }),
    ).toBe('updated')
    const refreshed = await selected(f, 'vault.entry', key.ownerDID, entry.entryID)
    const op = await verifySignedRecord(refreshed, VAULT_OP_KIND)
    const original = await verifySignedRecord(before, VAULT_OP_KIND)
    expect(op?.claim.meta.contentHLC).toBe(original?.claim.meta.contentHLC)
    expect(op?.claim.meta.consumer).toEqual({ current: true })
    expect(refreshed.hlc).not.toBe(before.hlc)
    expect(await f.store.getEntry(entry)).toMatchObject({ ...metadata, keyVersion: 2 })
    expect(await f.manager.readEntry(entry)).toEqual(bytes('token'))
    expect((await f.store.getKey(key))?.version).toBe(2)
  })

  test('refreshWrapping replaces evidence without opening a PIN gated wrapping', async () => {
    const f = await fixture()
    const key = await f.manager.createKey({
      ownerDID: f.identity.id,
      wrappings: [
        [
          { kind: 'did', recipientDID: f.identity.id },
          { kind: 'pin', input: bytes('1234'), cost: { m: 8, t: 1, p: 1 } },
        ],
      ],
    })
    const row = (await f.store.listWrappings(key))[0]
    if (!row) throw new Error('Missing wrapping')
    const before = await selected(f, 'vault.wrapping', key.ownerDID, row.wrappingID)
    const result = await f.manager.refreshWrapping({
      ...key,
      wrappingID: row.wrappingID,
      expectedOpHash: before.opHash,
      consumer: { current: true },
    })
    expect(result.opHash).not.toBe(before.opHash)
    expect(result.hlc > before.hlc).toBe(true)
    expect(result.payload).toEqual(before.payload)
    expect(await f.store.listWrappings(key)).toEqual([row])
    expect((await verifySignedRecord(result, VAULT_OP_KIND))?.claim.meta.consumer).toEqual({
      current: true,
    })
    expect(await selected(f, 'vault.wrapping', key.ownerDID, row.wrappingID)).toEqual(result)
  })

  test.each(['none', 'another recipient'] as const)(
    'rotation retains the highest openable historical source with %s current wrappings',
    async (receipt) => {
      const f = await fixture()
      const other = randomIdentity()
      const revoked = randomIdentity()
      const peer = await fixture(f.identity)
      const key = await f.manager.createKey({
        ownerDID: f.identity.id,
        wrappings: [f.identity, other, revoked].map((identity) => [
          { kind: 'did', recipientDID: identity.id },
        ]),
      })
      const entry = await f.manager.putEntry({
        ...key,
        entryID: 'old',
        plaintext: bytes('secret'),
        ...metadata,
      })
      await peer.manager.records.apply(await copies(f))
      await peer.manager.rotate({
        ...key,
        excludedRecipients: [revoked.id],
        reissue: [{ ...entry, action: 'skip' }],
      })
      const otherWrappings = new Set(
        (await peer.store.listWrappings({ ...key, keyVersion: 2 }))
          .filter((row) => row.recipientDID === other.id)
          .map((row) => row.wrappingID),
      )
      await f.manager.records.apply(
        (await copies(peer)).filter(
          (r) =>
            r.type !== 'vault.wrapping' ||
            (receipt === 'another recipient' && otherWrappings.has(r.id)),
        ),
      )
      expect(
        await f.manager.rotate({ ...key, sourceVersion: 1, excludedRecipients: [], reissue: [] }),
      ).toBe(3)
      const retained = await f.store.listWrappings({ ...key, keyVersion: 3 })
      expect(retained.map((w) => w.recipientDID).sort()).toEqual([f.identity.id, other.id].sort())
      expect(await f.manager.readEntry(entry)).toEqual(bytes('secret'))
      const reader = createVaultCoordinator({
        ...f.params,
        identity: other,
        principal: other.id,
        signer: other,
      })
      expect(await reader.readEntry(entry)).toEqual(bytes('secret'))
      const denied = createVaultCoordinator({
        ...f.params,
        identity: revoked,
        principal: revoked.id,
        signer: revoked,
      })
      await expect(denied.readEntry(entry)).rejects.toThrow()
    },
  )

  test.each(['consent', 'deletion', 'key move', 'rotation', 'revocation'] as const)(
    'refreshEntry refuses %s arriving after decryption',
    async (race) => {
      const f = await fixture()
      const peer = await fixture(f.identity)
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      const entry = await f.manager.putEntry({
        ...key,
        entryID: 'racing',
        plaintext: bytes('old'),
        ...metadata,
      })
      const before = await selected(f, 'vault.entry', key.ownerDID, entry.entryID)
      const target = await f.manager.createKey({ ownerDID: f.identity.id })
      await peer.manager.records.apply(await copies(f))
      if (race === 'consent') await peer.manager.updateEntry({ ...entry, plaintext: bytes('new') })
      if (race === 'deletion') await peer.manager.deleteEntry(entry)
      if (race === 'key move') await peer.manager.reKeyEntry({ ...entry, toKeyID: target.keyID })
      if (race === 'rotation' || race === 'revocation')
        await peer.manager.rotate({
          ...key,
          excludedRecipients: race === 'revocation' ? [f.identity.id] : [],
          reissue: [],
        })
      const record = await selected(
        peer,
        race === 'rotation'
          ? 'vault.key'
          : race === 'revocation'
            ? 'vault.revocation'
            : 'vault.entry',
        key.ownerDID,
        race === 'rotation'
          ? key.keyID
          : race === 'revocation'
            ? ((await copies(peer)).find((r) => r.type === 'vault.revocation')?.id ?? '')
            : entry.entryID,
      )
      await expect(
        injectAtClock(f, [record], (manager) =>
          manager.refreshEntry({ ...entry, expectedHLC: before.hlc }),
        ),
      ).rejects.toThrow()
      expect(await selected(f, 'vault.entry', key.ownerDID, entry.entryID)).toEqual(before)
      expect((await f.store.getKey(key))?.version).toBe(1)
    },
  )

  test.each(['copy', 'deletion', 'rotation', 'revocation'] as const)(
    'refreshWrapping refuses %s arriving during signing',
    async (race) => {
      const f = await fixture()
      const peer = await fixture(f.identity)
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      const row = (await f.store.listWrappings(key))[0]
      if (!row) throw new Error('Missing wrapping')
      const before = await selected(f, 'vault.wrapping', key.ownerDID, row.wrappingID)
      await peer.manager.records.apply(await copies(f))
      let injected: Array<SignedRecord>
      if (race === 'copy') {
        injected = [
          await peer.manager.refreshWrapping({
            ...key,
            wrappingID: row.wrappingID,
            expectedOpHash: before.opHash,
            consumer: { newer: true },
          }),
        ]
      } else if (race === 'deletion') {
        await peer.manager.addFactor({
          ...key,
          factor: { kind: 'pin', input: bytes('pin'), cost: { m: 8, t: 1, p: 1 } },
        })
        injected = [await selected(peer, 'vault.wrapping', key.ownerDID, row.wrappingID)]
      } else {
        await peer.manager.rotate({
          ...key,
          excludedRecipients: race === 'revocation' ? [f.identity.id] : [],
          reissue: [],
        })
        injected = (await copies(peer)).filter(
          (r) => r.type === (race === 'rotation' ? 'vault.key' : 'vault.revocation'),
        )
      }
      await expect(
        injectAtClock(f, injected, (manager) =>
          manager.refreshWrapping({
            ...key,
            wrappingID: row.wrappingID,
            expectedOpHash: before.opHash,
            consumer: { current: true },
          }),
        ),
      ).rejects.toThrow()
      expect(await selected(f, 'vault.wrapping', key.ownerDID, row.wrappingID)).toEqual(before)
    },
  )

  test('refreshEntry returns superseded or absent after consent and deletion, never recreating the entry', async () => {
    const f = await fixture()
    const key = await f.manager.createKey({ ownerDID: f.identity.id })
    const entry = await f.manager.putEntry({
      ...key,
      entryID: 'cas',
      plaintext: bytes('old'),
      ...metadata,
    })
    const before = await selected(f, 'vault.entry', key.ownerDID, entry.entryID)
    await f.manager.updateEntry({ ...entry, plaintext: bytes('new') })
    expect(await f.manager.refreshEntry({ ...entry, expectedHLC: before.hlc })).toBe('superseded')
    expect(await f.manager.readEntry(entry)).toEqual(bytes('new'))
    const target = await f.manager.createKey({ ownerDID: f.identity.id })
    await f.manager.reKeyEntry({ ...entry, toKeyID: target.keyID })
    expect(await f.manager.refreshEntry({ ...entry, expectedHLC: before.hlc })).toBe('superseded')
    expect((await f.store.getEntry(entry))?.keyID).toBe(target.keyID)
    expect(await f.manager.readEntry(entry)).toEqual(bytes('new'))
    await f.manager.deleteEntry(entry)
    expect(await f.manager.refreshEntry({ ...entry, expectedHLC: before.hlc })).toBe('absent')
    expect(await f.store.getEntry(entry)).toBeUndefined()
  })

  test.each(['winning', 'losing'] as const)(
    'concurrent repairs read the %s entry projection for every survivor without writes',
    async (projection) => {
      const a = await fixture()
      const b = await fixture(a.identity)
      const survivor = randomIdentity()
      const removed = randomIdentity()
      const key = await a.manager.createKey({
        ownerDID: a.identity.id,
        wrappings: [a.identity, survivor, removed].map((identity) => [
          { kind: 'did', recipientDID: identity.id },
        ]),
      })
      const entry = await a.manager.putEntry({
        ...key,
        entryID: 'shared',
        plaintext: bytes('same'),
        ...metadata,
      })
      await b.manager.records.apply(await copies(a))
      await a.manager.putEntry({
        ...key,
        entryID: 'a-only',
        plaintext: bytes('unique'),
        ...metadata,
      })
      await b.manager.updateEntry({ ...entry, plaintext: bytes('newer') })
      await a.manager.rotate({ ...key, excludedRecipients: [removed.id], reissue: [] })
      await b.manager.rotate({ ...key, excludedRecipients: [removed.id], reissue: [] })
      const forkA = await copies(a)
      const forkB = await copies(b)
      await a.manager.records.apply(forkB)
      await b.manager.records.apply(forkA)
      const markerValue = { repair: 'same authenticated input set' }
      for (const f of [a, b])
        expect(
          await f.manager.repairFork({
            ...key,
            excludedRecipients: [],
            reissue: [],
            consumer: markerValue,
          }),
        ).toEqual({ status: 'rotated', version: 3 })
      const repairedA = await copies(a)
      const repairedB = await copies(b)
      const branches = [
        ...(await a.manager.records.listKeyBranches({ ...key, keyVersion: 3 })),
        ...(await b.manager.records.listKeyBranches({ ...key, keyVersion: 3 })),
      ]
      const winningOp = selectWinningBranch(branches.map((branch) => branch.introducingOp))
      const winningID = `${winningOp.claim.hlc}:${winningOp.opHash}`
      const aBranch = branches[0]
      if (!aBranch) throw new Error('Missing repair branch')
      const [winning, losing] =
        aBranch.branchID === winningID ? [repairedA, repairedB] : [repairedB, repairedA]
      const selectedEntries = (projection === 'winning' ? winning : losing).filter(
        (record) => record.type === 'vault.entry',
      )
      const approve = async (request: {
        entry: SignedRecord
        entryBranch: SignedRecord
        winningBranch: SignedRecord
      }) => {
        const own = await verifySignedRecord(request.entryBranch, VAULT_OP_KIND)
        const winner = await verifySignedRecord(request.winningBranch, VAULT_OP_KIND)
        return (
          marker(own?.claim.meta.consumer) === markerValue.repair &&
          marker(winner?.claim.meta.consumer) === markerValue.repair
        )
      }
      for (const [f, incoming] of [
        [a, repairedB],
        [b, repairedA],
      ] as const) {
        await f.manager.records.apply(incoming)
        await f.manager.records.adapter.transaction(async (tx) => {
          for (const record of selectedEntries) await tx.putCopy(record)
        })
        const before = await copies(f)
        f.queries.length = 0
        for (const identity of [a.identity, survivor]) {
          const manager = createVaultCoordinator({
            ...f.params,
            identity,
            principal: identity.id,
            signer: identity,
            authorizeEquivalentBranch: approve,
          })
          expect(await manager.readEntry(entry)).toEqual(bytes('newer'))
          expect(await manager.readEntry({ ownerDID: key.ownerDID, entryID: 'a-only' })).toEqual(
            bytes('unique'),
          )
        }
        const revoked = createVaultCoordinator({
          ...f.params,
          identity: removed,
          principal: removed.id,
          signer: removed,
          authorizeEquivalentBranch: approve,
        })
        await expect(revoked.readEntry(entry)).rejects.toThrow()
        if (projection === 'losing') {
          await expect(f.manager.readEntry(entry)).rejects.toMatchObject({
            name: 'VaultSupersededBranch',
          })
          for (const approval of [false, undefined, 'true']) {
            const denied = createVaultCoordinator({
              ...f.params,
              authorizeEquivalentBranch: async () => approval as boolean,
            })
            await expect(denied.readEntry(entry)).rejects.toMatchObject({
              name: 'VaultSupersededBranch',
            })
          }
        }
        expect(f.queries.filter((query) => /^(insert|update|delete)/i.test(query.sql))).toEqual([])
        expect(await copies(f)).toEqual(before)
        expect((await f.store.getKey(key))?.version).toBe(3)
      }
    },
    REPAIR_EXCHANGE_TIMEOUT,
  )

  test('refresh refuses tampered projections and denied current authority before signing', async () => {
    const { sql } = await import('@hozon/db')
    const f = await fixture()
    const key = await f.manager.createKey({ ownerDID: f.identity.id })
    const entry = await f.manager.putEntry({
      ...key,
      entryID: 'metadata',
      plaintext: bytes('secret'),
      ...metadata,
    })
    const row = await f.store.getEntry(entry)
    const wrapping = (await f.store.listWrappings(key))[0]
    if (!row || !wrapping) throw new Error('Missing material')
    const record = await selected(f, 'vault.wrapping', key.ownerDID, wrapping.wrappingID)
    const denied = createVaultCoordinator({
      ...f.params,
      authority: { authorize: async () => false },
    })
    await expect(denied.refreshEntry({ ...entry, expectedHLC: row.hlc })).rejects.toMatchObject({
      name: 'VaultNotAuthorized',
    })
    await expect(
      denied.refreshWrapping({
        ...key,
        wrappingID: wrapping.wrappingID,
        expectedOpHash: record.opHash,
        consumer: null,
      }),
    ).rejects.toMatchObject({ name: 'VaultNotAuthorized' })
    await sql`update ${sql.table('vault_entries')} set label = ${'forged'} where entry_id = ${entry.entryID}`.execute(
      f.raw,
    )
    await expect(f.manager.refreshEntry({ ...entry, expectedHLC: row.hlc })).rejects.toMatchObject({
      name: 'VaultTampered',
    })
    await sql`update ${sql.table('vault_wrappings')} set recipient_did = ${randomIdentity().id} where wrapping_id = ${wrapping.wrappingID}`.execute(
      f.raw,
    )
    await expect(
      f.manager.refreshWrapping({
        ...key,
        wrappingID: wrapping.wrappingID,
        expectedOpHash: record.opHash,
        consumer: null,
      }),
    ).rejects.toMatchObject({ name: 'VaultTampered' })
  })

  test('wrapping refresh replaces expired evidence and admits only current evidence on a fresh recipient', async () => {
    const f = await fixture()
    const key = await f.manager.createKey({
      ownerDID: f.identity.id,
      consumer: { expired: true },
      wrappings: [
        [
          { kind: 'did', recipientDID: f.identity.id },
          { kind: 'pin', input: bytes('pin'), cost: { m: 8, t: 1, p: 1 } },
        ],
      ],
    })
    const row = (await f.store.listWrappings(key))[0]
    if (!row || f.params.mode !== 'replicated') throw new Error('Missing wrapping')
    const before = await selected(f, 'vault.wrapping', key.ownerDID, row.wrappingID)
    const validate: NonNullable<typeof f.params.records.validateConsumerMetadata> = async (
      consumer,
      request,
    ) => {
      return (
        request.op.claim.type !== 'vault.wrapping' ||
        (consumer !== null &&
          typeof consumer === 'object' &&
          'current' in consumer &&
          consumer.current === true)
      )
    }
    const manager = createVaultCoordinator({
      ...f.params,
      identity: null,
      records: { ...f.params.records, validateConsumerMetadata: validate },
    })
    await expect(
      manager.refreshWrapping({
        ...key,
        wrappingID: row.wrappingID,
        expectedOpHash: before.opHash,
        consumer: { expired: true },
      }),
    ).rejects.toMatchObject({ name: 'VaultWriteConflict' })
    expect(await selected(f, 'vault.wrapping', key.ownerDID, row.wrappingID)).toEqual(before)
    const refreshed = await manager.refreshWrapping({
      ...key,
      wrappingID: row.wrappingID,
      expectedOpHash: before.opHash,
      consumer: { current: true },
    })
    const recipient = await fixture(f.identity)
    if (recipient.params.mode !== 'replicated') throw new Error('Expected replicated fixture')
    const receiver = createVaultCoordinator({
      ...recipient.params,
      records: { ...recipient.params.records, validateConsumerMetadata: validate },
    })
    expect((await receiver.records.apply([refreshed])).parked).toHaveLength(1)
    await receiver.records.apply((await copies(f)).filter((r) => r.type !== 'vault.wrapping'))
    expect((await receiver.records.apply([before])).rejected).toHaveLength(1)
    expect((await receiver.records.apply([refreshed])).applied).toBe(1)
    const opened = await receiver.openKey({ ...key, inputs: { pin: bytes('pin') } })
    expect(opened.version).toBe(1)
    opened.contentKey.fill(0)
  })

  test('refresh mutations join host rollback', async () => {
    const f = await fixture()
    const key = await f.manager.createKey({ ownerDID: f.identity.id })
    const entry = await f.manager.putEntry({
      ...key,
      entryID: 'atomic',
      plaintext: bytes('secret'),
      ...metadata,
    })
    const row = await f.store.getEntry(entry)
    const wrapping = (await f.store.listWrappings(key))[0]
    if (!row || !wrapping) throw new Error('Missing material')
    const record = await selected(f, 'vault.wrapping', key.ownerDID, wrapping.wrappingID)
    await f.manager.rotate({
      ...key,
      excludedRecipients: [],
      reissue: [{ ...entry, action: 'skip' }],
    })
    const before = await copies(f)
    await expect(
      f.db.withTransaction(async (provider) => {
        const manager = createVaultCoordinator({
          ...f.params,
          store: await getVaultStore(provider),
        })
        expect(await manager.refreshEntry({ ...entry, expectedHLC: row.hlc })).toBe('updated')
        const current = (
          await (await getVaultStore(provider)).listWrappings({ ...key, keyVersion: 2 })
        )[0]
        if (!current) throw new Error('Missing current wrapping')
        const copy = (
          await manager.records.adapter.get({
            type: 'vault.wrapping',
            owner: key.ownerDID,
            id: current.wrappingID,
          })
        )?.copies[0]
        if (!copy) throw new Error('Missing current copy')
        await manager.refreshWrapping({
          ...key,
          wrappingID: current.wrappingID,
          expectedOpHash: copy.opHash,
          consumer: { renewed: true },
        })
        throw new Error('host rollback')
      }),
    ).rejects.toThrow('host rollback')
    expect(await copies(f)).toEqual(before)
    expect(await f.store.getEntry(entry)).toEqual(row)
    await expect(
      f.manager.refreshWrapping({
        ...key,
        wrappingID: wrapping.wrappingID,
        expectedOpHash: record.opHash,
        consumer: null,
      }),
    ).rejects.toThrow()
  })

  test.each(['different', 'missing'] as const)(
    'equivalent branch policy refuses %s signed repair markers',
    async (value) => {
      const a = await fixture()
      const b = await fixture(a.identity)
      const key = await a.manager.createKey({ ownerDID: a.identity.id })
      const entry = await a.manager.putEntry({
        ...key,
        entryID: 'shared',
        plaintext: bytes('same'),
        ...metadata,
      })
      await b.manager.records.apply(await copies(a))
      await a.manager.rotate({
        ...key,
        excludedRecipients: [],
        reissue: [],
        consumer: { repair: 'first' },
      })
      await b.manager.rotate({
        ...key,
        excludedRecipients: [],
        reissue: [],
        consumer: value === 'different' ? { repair: 'second' } : null,
      })
      const left = await copies(a)
      const right = await copies(b)
      const branches = [
        ...(await a.manager.records.listKeyBranches({ ...key, keyVersion: 2 })),
        ...(await b.manager.records.listKeyBranches({ ...key, keyVersion: 2 })),
      ]
      const op = selectWinningBranch(branches.map((branch) => branch.introducingOp))
      const winningID = `${op.claim.hlc}:${op.opHash}`
      const losing = branches[0]?.branchID === winningID ? right : left
      await a.manager.records.apply(right)
      const record = losing.find((r) => r.type === 'vault.entry')
      if (!record) throw new Error('Missing entry')
      await a.manager.records.adapter.transaction(async (tx) => {
        await tx.putCopy(record)
      })
      const manager = createVaultCoordinator({
        ...a.params,
        authorizeEquivalentBranch: async ({ entryBranch, winningBranch }) => {
          const own = marker(
            (await verifySignedRecord(entryBranch, VAULT_OP_KIND))?.claim.meta.consumer,
          )
          const winner = marker(
            (await verifySignedRecord(winningBranch, VAULT_OP_KIND))?.claim.meta.consumer,
          )
          return own !== undefined && own === winner
        },
      })
      await expect(manager.readEntry(entry)).rejects.toMatchObject({
        name: 'VaultSupersededBranch',
      })
    },
  )

  test('historical-source rotation refuses an empty retained set despite a cached source', async () => {
    const f = await fixture()
    const peer = await fixture(f.identity)
    const key = await f.manager.createKey({ ownerDID: f.identity.id })
    const entry = await f.manager.putEntry({
      ...key,
      entryID: 'cached',
      plaintext: bytes('secret'),
      ...metadata,
    })
    await f.manager.unlock(key)
    const original = (await f.store.listWrappings(key))[0]
    if (!original) throw new Error('Missing wrapping')
    await peer.manager.records.apply(await copies(f))
    await peer.manager.addFactor({
      ...key,
      factor: { kind: 'pin', input: bytes('pin'), cost: { m: 8, t: 1, p: 1 } },
    })
    await peer.manager.rotate({
      ...key,
      inputs: { pin: bytes('pin') },
      excludedRecipients: [],
      reissue: [{ ...entry, action: 'skip' }],
    })
    await f.manager.records.apply(
      (await copies(peer)).filter(
        (record) =>
          record.type === 'vault.key' ||
          record.type === 'vault.key-branch' ||
          (record.type === 'vault.wrapping' && record.id === original.wrappingID),
      ),
    )
    expect(await f.store.listWrappings({ ...key, keyVersion: 1 })).toHaveLength(0)
    const before = await copies(f)
    const row = await f.store.getEntry(entry)
    await expect(
      f.manager.rotate({ ...key, sourceVersion: 1, excludedRecipients: [], reissue: [] }),
    ).rejects.toThrow()
    expect(await copies(f)).toEqual(before)
    expect(await f.store.getEntry(entry)).toEqual(row)
    expect((await f.store.getKey(key))?.version).toBe(2)
    expect(await f.manager.readEntry(entry)).toEqual(bytes('secret'))
  })

  test.each([undefined, 1])(
    'rotation authenticates each retained PIN with sourceVersion %s',
    async (sourceVersion) => {
      const f = await fixture()
      const key = await f.manager.createKey({
        ownerDID: f.identity.id,
        wrappings: [
          [{ kind: 'did', recipientDID: f.identity.id }],
          [
            { kind: 'did', recipientDID: f.identity.id },
            { kind: 'pin', input: bytes('pin'), cost: { m: 8, t: 1, p: 1 } },
          ],
        ],
      })
      const before = await copies(f)
      const wrappings = await f.store.listWrappings(key)
      await expect(
        f.manager.rotate({
          ...key,
          sourceVersion,
          inputs: { pin: bytes('wrong') },
          excludedRecipients: [],
          reissue: [],
        }),
      ).rejects.toMatchObject({ name: 'VaultPinRejected' })
      expect(await copies(f)).toEqual(before)
      expect(await f.store.listWrappings(key)).toEqual(wrappings)
      expect((await f.store.getKey(key))?.version).toBe(1)
      expect(
        await f.manager.rotate({
          ...key,
          sourceVersion,
          inputs: { pin: bytes('pin') },
          excludedRecipients: [],
          reissue: [],
        }),
      ).toBe(2)
      const pin = (await f.store.listWrappings({ ...key, keyVersion: 2 })).find((w) =>
        w.descriptors.some((d) => d.kind === 'pin'),
      )
      if (!pin) throw new Error('Missing PIN wrapping')
      const { getSuite } = await import('@kokuin/vault')
      const opened = await getSuite(1).unwrap({
        ...pin,
        identity: f.identity,
        inputs: { pin: bytes('pin') },
      })
      opened.fill(0)
    },
  )

  test('historical-source rotation refuses to drop a surviving recipient with an unavailable secret', async () => {
    const f = await fixture()
    const other = randomIdentity()
    const peer = await fixture(other)
    const key = await f.manager.createKey({
      ownerDID: f.identity.id,
      wrappings: [
        [{ kind: 'did', recipientDID: f.identity.id }],
        [
          { kind: 'did', recipientDID: other.id },
          { kind: 'pin', input: bytes('pin'), cost: { m: 8, t: 1, p: 1 } },
        ],
      ],
    })
    await peer.manager.records.apply(await copies(f))
    await peer.manager.rotate({
      ...key,
      inputs: { pin: bytes('pin') },
      excludedRecipients: [],
      reissue: [],
    })
    await f.manager.records.apply(
      (await copies(peer)).filter((record) => record.type !== 'vault.wrapping'),
    )
    const before = await copies(f)
    await expect(
      f.manager.rotate({ ...key, sourceVersion: 1, excludedRecipients: [], reissue: [] }),
    ).rejects.toThrow()
    expect(await copies(f)).toEqual(before)
    expect((await f.store.getKey(key))?.version).toBe(2)
  })

  test('concurrent historical-source rotations refuse the second version advance', async () => {
    const f = await fixture()
    const key = await f.manager.createKey({ ownerDID: f.identity.id })
    await f.db.withTransaction(async (provider) => {
      const store = await getVaultStore(provider)
      const a = createVaultCoordinator({ ...f.params, store })
      const b = createVaultCoordinator({ ...f.params, store })
      const results = await Promise.allSettled(
        [a, b].map((manager) =>
          manager.rotate({ ...key, sourceVersion: 1, excludedRecipients: [], reissue: [] }),
        ),
      )
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
      const refused = results.find((result) => result.status === 'rejected')
      expect(refused).toMatchObject({ status: 'rejected', reason: { name: 'VaultWriteConflict' } })
    })
    expect((await f.store.getKey(key))?.version).toBe(2)
  })

  test.each(['wrong PIN', 'missing secret', 'missing proof', 'unavailable source'] as const)(
    'historical-source rotation rolls back for %s',
    async (failure) => {
      const f = await fixture()
      const key = await f.manager.createKey({
        ownerDID: f.identity.id,
        wrappings: [
          [
            { kind: 'did', recipientDID: f.identity.id },
            { kind: 'pin', input: bytes('pin'), cost: { m: 8, t: 1, p: 1 } },
          ],
        ],
      })
      if (failure === 'missing proof') {
        const { sql } = await import('@hozon/db')
        await sql`delete from ${sql.table('vault_key_branches')}`.execute(f.raw)
      }
      const before = await copies(f)
      const manager =
        failure === 'unavailable source'
          ? createVaultCoordinator({ ...f.params, identity: null })
          : f.manager
      await expect(
        manager.rotate({
          ...key,
          sourceVersion: 1,
          excludedRecipients: [],
          reissue: [],
          inputs:
            failure === 'missing secret'
              ? undefined
              : { pin: bytes(failure === 'wrong PIN' ? 'wrong' : 'pin') },
        }),
      ).rejects.toThrow()
      expect(await copies(f)).toEqual(before)
      expect((await f.store.getKey(key))?.version).toBe(1)
    },
  )
})
