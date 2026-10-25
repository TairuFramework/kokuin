import type { RecordTypeDefinition, VisibilityContext } from '@kokuin/records'
import {
  compareRecordOps,
  recordClaimDigest,
  recordDecisionDigest,
  recordPayloadDigest,
  verifyHolderProof,
  visibleTo,
} from '@kokuin/records'
import { randomIdentity } from '@kokuin/token'
import { fromB64U, fromUTF, toB64U } from '@sozai/codec'
import { describe, expect, test } from 'vitest'

import type { CredentialAuthorityRequest } from '../src/index.js'
import {
  decodeVaultRecord,
  encodeVaultRecordPayload,
  selectWinningBranch,
  VAULT_OP_KIND,
  vaultHolderTypes,
  vaultKeyVersionReader,
  vaultProofAuthorizer,
  vaultRecordTypes,
  vaultRevocationRecordID,
} from '../src/index.js'
import {
  chain,
  dependent,
  memoryStore,
  OP_KIND,
  resign,
  signed,
  stamp,
  UNIQUE,
  verified,
} from './record-fixture.js'

const reasons = (result: Awaited<ReturnType<ReturnType<typeof memoryStore>['apply']>>) =>
  result.rejected.map((r) => r.reason)

function definition(type: string, peer = memoryStore()): RecordTypeDefinition {
  const result = vaultRecordTypes({ ...peer.hooks, opKind: OP_KIND }).get(type)
  if (!result) throw new Error(`Missing definition ${type}`)
  return result
}

describe('vault record registration and authority', () => {
  test('registers five policies and declares both entry dependency types', () => {
    const peer = memoryStore()
    const types = vaultRecordTypes({ ...peer.hooks, opKind: OP_KIND })
    expect(Object.fromEntries([...types].map(([type, def]) => [type, def.policy.kind]))).toEqual({
      'vault.key': 'monotonic',
      'vault.key-branch': 'immutable',
      'vault.wrapping': 'lww',
      'vault.entry': 'monotonic',
      'vault.revocation': 'lww',
    })
    expect(types.get('vault.entry')?.dependsOn).toEqual(['vault.key', 'vault.key-branch'])
    expect(types.get('vault.key')?.dependsOn).toEqual([])
    expect(types.get('vault.key-branch')?.dependsOn).toEqual(['vault.key'])
    expect(types.get('vault.wrapping')?.dependsOn).toEqual(['vault.key', 'vault.key-branch'])
    expect(types.get('vault.revocation')?.dependsOn).toEqual(['vault.key'])
    expect(VAULT_OP_KIND).toBe(OP_KIND)
    // @ts-expect-error a replay domain is mandatory
    expect(() => vaultRecordTypes(peer.hooks)).toThrow()
    expect(() => vaultRecordTypes({ ...peer.hooks, opKind: '' })).toThrow()
  })

  test('structural prechecks never call authority and malformed addresses refuse before parking', async () => {
    const owner = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner)
    const wrapping = await dependent(owner, source, 'vault.wrapping')
    const op = await verified(wrapping)
    for (const patch of [
      { keyID: 'invalid' },
      { branchRecordID: 'invalid' },
      { branchID: '' },
      { keyVersion: 2 ** 53 },
    ]) {
      const malformed = await resign(owner, wrapping, { meta: { ...op.claim.meta, ...patch } })
      const result = await peer.apply([malformed], {
        authority: {
          authorize: async () => {
            throw new Error('Authority before structure')
          },
        },
      })
      expect(reasons(result)).toEqual(['unauthorized'])
      expect(result.parked).toEqual([])
    }
    const types = vaultRecordTypes({
      ...peer.hooks,
      opKind: OP_KIND,
      authority: {
        authorize: async () => {
          throw new Error('Contextual precheck')
        },
      },
    })
    expect(await types.get('vault.wrapping')?.precheck?.(op, wrapping)).toBe(true)
    const stranger = await dependent(randomIdentity(), source, 'vault.wrapping')
    expect((await peer.apply([stranger])).parked).toEqual([stranger])
  })

  test('passes verified fields and the identical opaque context with transaction-bound reads', async () => {
    const owner = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner, { consumer: { evidence: ['opaque', 7] } })
    const context = { requester: randomIdentity().id, channel: new Map([['id', 7]]) }
    const requests: Array<CredentialAuthorityRequest> = []
    const result = await peer.apply(
      [source.branch, source.key],
      {
        authority: {
          async authorize(request) {
            requests.push(request)
            expect(request.source).toBe('record')
            expect(request.transportContext).toBe(context)
            expect(request.owner).toBe(owner.id)
            expect(request.issuer).toBe(owner.id)
            expect(request.verb).toBe('administer')
            expect(request.store).not.toBe(peer.store)
            expect(request.recordKey).toEqual({
              type: request.op.claim.type,
              owner: owner.id,
              id: request.op.claim.id,
            })
            expect(request.record.opHash).toBe(request.op.opHash)
            if (request.op.claim.type === 'vault.key-branch')
              expect(await request.store.get(source.key)).not.toBeNull()
            return true
          },
        },
      },
      context,
    )
    expect(result.applied).toBe(2)
    expect(requests).toHaveLength(3)
    expect((await verified(source.key)).claim.meta).not.toHaveProperty('transportContext')
    const other = await chain(owner, { version: 2 })
    expect(
      reasons(await peer.apply([other.key], { authority: { authorize: async () => false } })),
    ).toEqual(['unauthorized'])
    expect((await peer.store.get(source.key))?.copies[0]?.opHash).toBe(source.key.opHash)
  })

  test('consumer metadata refusal has no fallback, including embedded introducing keys', async () => {
    const owner = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner, { consumer: { permit: false } })
    expect(
      reasons(await peer.apply([source.key], { validateConsumerMetadata: async () => false })),
    ).toEqual(['unauthorized'])
    await peer.apply([source.key])
    const op = await verified(source.branch)
    const branch = await resign(owner, source.branch, {
      meta: { ...op.claim.meta, consumer: { permit: true } },
    })
    expect(
      reasons(
        await peer.apply([branch], {
          validateConsumerMetadata: async (value) => (value as { permit: boolean }).permit,
        }),
      ),
    ).toEqual(['unauthorized'])
    expect(await peer.store.get(branch)).toBeNull()
  })

  test('another replay domain refuses ordinary and embedded operations', async () => {
    const owner = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner)
    const foreign = await resign(owner, source.key, {}, 'other/vault-op')
    expect(reasons(await peer.apply([foreign]))).toEqual(['signature'])
    await peer.apply([source.key])
    const payload = encodeVaultRecordPayload('vault.key-branch', {
      authorDID: owner.id,
      hlc: foreign.hlc,
      opJWT: foreign.opJWT,
      opHash: foreign.opHash,
      suite: 1,
    })
    const branch = await signed(owner, {
      type: 'vault.key-branch',
      id: recordPayloadDigest(payload) as string,
      owner: owner.id,
      hlc: source.branch.hlc,
      payload,
      meta: {
        keyID: source.keyID,
        keyVersion: 1,
        branchID: `${foreign.hlc}:${foreign.opHash}`,
        consumer: {},
      },
    })
    expect(reasons(await peer.apply([branch]))).toEqual(['unauthorized'])
    const custom = 'example/vault-op'
    const types = vaultRecordTypes({ ...peer.hooks, opKind: custom })
    const customRecord = await resign(owner, source.key, {}, custom)
    const op = await import('@kokuin/records').then((r) =>
      r.verifySignedRecord(customRecord, custom),
    )
    if (!op) throw new Error('Custom domain fixture')
    expect(await types.get('vault.key')?.precheck?.(op, customRecord)).toBe(true)
  })
})

describe('key ordering and authenticated branches', () => {
  test('owner commitment and payload state cannot be overridden by permissive authority', async () => {
    const owner = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner)
    const op = await verified(source.key)
    const wrongUnique = await resign(owner, source.key, {
      meta: { ...op.claim.meta, keyUnique: toB64U(new Uint8Array(16).fill(9)) },
    })
    const wrongOwner = await resign(randomIdentity(), source.key, { owner: randomIdentity().id })
    const wrongState = await resign(owner, source.key, {
      meta: { ...op.claim.meta, state: 'retired' },
    })
    expect(reasons(await peer.apply([wrongUnique, wrongOwner, wrongState]))).toEqual([
      'unauthorized',
      'unauthorized',
      'unauthorized',
    ])
    expect((await peer.apply([source.key])).applied).toBe(1)
    expect(fromB64U(op.claim.meta.keyUnique as string)).toEqual(UNIQUE)
  })

  test('version, retirement and deletion outrank operation clocks in either arrival order', async () => {
    const owner = randomIdentity()
    const one = await chain(owner, { counter: 400 })
    const two = await chain(owner, { version: 2, counter: 20 })
    const retired = await chain(owner, { version: 2, state: 'retired', counter: 30 })
    const op = await verified(two.key)
    const tombstone = await resign(owner, two.key, {
      hlc: stamp(5),
      payload: null,
      meta: { ...op.claim.meta, state: 'deleted' },
    })
    for (const order of [
      [one.key, two.key, retired.key],
      [retired.key, two.key, one.key],
    ]) {
      const peer = memoryStore()
      await peer.apply(order)
      expect((await peer.store.get(one.key))?.copies[0]?.opHash).toBe(retired.key.opHash)
      await peer.apply([tombstone, one.key, two.key, retired.key])
      expect((await peer.store.get(one.key))?.copies[0]?.payload).toBeNull()
    }
  })

  test('forks retain both proofs while the head and branch selector choose claim digest before hash', async () => {
    const owner = randomIdentity()
    let pair:
      | { winner: Awaited<ReturnType<typeof chain>>; loser: Awaited<ReturnType<typeof chain>> }
      | undefined
    for (let counter = 20; counter < 148; counter += 2) {
      const a = await chain(owner, { version: 2, counter })
      const b = await chain(owner, { version: 2, counter: counter + 1 })
      const [winner, loser] =
        (await recordDecisionDigest(a.key, OP_KIND)) > (await recordDecisionDigest(b.key, OP_KIND))
          ? [a, b]
          : [b, a]
      if (winner.key.opHash < loser.key.opHash) {
        pair = { winner, loser }
        break
      }
    }
    if (!pair) throw new Error('No opposing hash fixture')
    for (const order of [
      [pair.winner, pair.loser],
      [pair.loser, pair.winner],
    ]) {
      const peer = memoryStore()
      const result = await peer.apply(order.flatMap((s) => [s.key, s.branch]))
      expect(result.conflicts.some((c) => c.forked)).toBe(true)
      expect((await peer.store.get(pair.winner.key))?.copies[0]?.opHash).toBe(
        pair.winner.key.opHash,
      )
      expect(await peer.store.list(['vault.key-branch'])).toHaveLength(2)
      expect(selectWinningBranch(await Promise.all(order.map((s) => verified(s.key)))).opHash).toBe(
        pair.winner.key.opHash,
      )
    }
  })

  test('equal-claim branches use op hash as the remaining tie-break', async () => {
    const owner = randomIdentity()
    const source = await chain(owner)
    const other = await resign(randomIdentity(), source.key)
    const ops = [await verified(source.key), await verified(other)] as const
    expect(recordClaimDigest(ops[0].claim)).toBe(recordClaimDigest(ops[1].claim))
    const expected = [source.key.opHash, other.opHash].sort().at(-1)
    expect(selectWinningBranch(ops).opHash).toBe(expected)
    expect(selectWinningBranch([...ops].reverse()).opHash).toBe(expected)
    expect(() => selectWinningBranch([])).toThrow(RangeError)
  })

  test('branch proof binds label, key, owner, version, author, suite, hash and payload address', async () => {
    const owner = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner)
    await peer.apply([source.key])
    const op = await verified(source.branch)
    const decoded = decodeVaultRecord(source.branch, op.claim.meta)
    if (decoded.type !== 'vault.key-branch') throw new Error('Fixture type')
    const base = decoded.payload
    for (const patch of [
      { authorDID: randomIdentity().id },
      { hlc: stamp(11) },
      { opHash: toB64U(new Uint8Array(32)) },
      { suite: 2 },
      { opJWT: `${base.opJWT}=` },
    ]) {
      const payload = encodeVaultRecordPayload('vault.key-branch', { ...base, ...patch })
      const broken = await resign(owner, source.branch, {
        id: recordPayloadDigest(payload) as string,
        payload,
      })
      expect(reasons(await peer.apply([broken]))).toEqual(['unauthorized'])
    }
    for (const patch of [{ branchID: `${stamp(20)}:${source.key.opHash}` }, { keyVersion: 0 }]) {
      const broken = await resign(owner, source.branch, { meta: { ...op.claim.meta, ...patch } })
      expect(reasons(await peer.apply([broken]))).toEqual(['unauthorized'])
    }
    const wrongID = await resign(owner, source.branch, { id: toB64U(new Uint8Array(32)) })
    const deleted = await resign(owner, source.branch, { payload: null })
    expect(reasons(await peer.apply([wrongID, deleted]))).toEqual(['unauthorized', 'unauthorized'])
    const foreign = await resign(owner, source.branch, { owner: randomIdentity().id })
    expect((await peer.apply([foreign])).parked).toEqual([foreign])
    const refused = await peer.apply([source.branch], {
      authority: { authorize: async (request) => request.op.claim.type !== 'vault.key' },
    })
    expect(reasons(refused)).toEqual(['unauthorized'])
    expect((await peer.apply([source.branch])).applied).toBe(1)
  })
})

describe('dependent records', () => {
  test.each(['vault.entry', 'vault.wrapping'] as const)(
    '%s needs exact owner, key, version and live branch with no empty provenance',
    async (type) => {
      const owner = randomIdentity()
      const peer = memoryStore()
      const exact = await chain(owner)
      const other = await chain(owner, { counter: 11 })
      await peer.apply([other.key, other.branch])
      const record = await dependent(owner, exact, type)
      expect((await peer.apply([record])).parked).toEqual([record])
      expect((await peer.apply([record, exact.branch])).applied).toBe(2)
      const op = await verified(record)
      const wrongVersion = await resign(owner, record, {
        meta: { ...op.claim.meta, keyVersion: 2 },
      })
      const foreign = await resign(owner, record, { owner: randomIdentity().id })
      for (const missing of [wrongVersion, foreign])
        expect((await peer.apply([missing])).parked).toEqual([missing])
      const empty = await resign(owner, record, { meta: { ...op.claim.meta, branchID: '' } })
      expect(reasons(await peer.apply([empty]))).toEqual(['unauthorized'])
      expect((await peer.store.get(record))?.copies[0]?.payload).toEqual(record.payload)
    },
  )

  test('entry content intent precedes key version including node IDs and tombstones', async () => {
    const owner = randomIdentity()
    const one = await chain(owner)
    const two = await chain(owner, { version: 2 })
    const old = await dependent(owner, two, 'vault.entry', { counter: 200, contentCounter: 90 })
    const newer = await dependent(owner, one, 'vault.entry', { counter: 300, contentCounter: 100 })
    const refresh = await dependent(owner, two, 'vault.entry', {
      counter: 400,
      contentCounter: 100,
    })
    const gone = await dependent(owner, one, 'vault.entry', {
      counter: 500,
      contentCounter: 101,
      deleted: true,
    })
    for (const order of [
      [old, newer, refresh],
      [refresh, newer, old],
    ]) {
      const peer = memoryStore()
      await peer.apply([one.key, one.branch, two.key, two.branch, ...order])
      expect((await peer.store.get(old))?.copies[0]?.opHash).toBe(refresh.opHash)
      await peer.apply([gone, refresh])
      expect((await peer.store.get(old))?.copies[0]?.payload).toBeNull()
      expect(peer.candidates().map((r) => r.opHash)).toContain(gone.opHash)
    }
    const a = await dependent(owner, two, 'vault.entry', { contentCounter: 90, nodeID: 'a' })
    const z = await dependent(owner, one, 'vault.entry', { contentCounter: 90, nodeID: 'aa' })
    expect(
      compareRecordOps(await verified(z), await verified(a), definition('vault.entry').policy)
        .status,
    ).toBe('apply')
  })

  test('malformed or future content stamps refuse before dependencies; tombstone versions remain bounded', async () => {
    const owner = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner)
    const entry = await dependent(owner, source, 'vault.entry')
    const op = await verified(entry)
    for (const contentHLC of [stamp(200), 'not-a-clock', stamp(90).replace('00000090', '90')]) {
      const broken = await resign(owner, entry, { meta: { ...op.claim.meta, contentHLC } })
      expect(reasons(await peer.apply([broken]))).toEqual(['unauthorized'])
    }
    await peer.apply([source.key])
    const tombstone = await resign(owner, entry, {
      payload: null,
      meta: { ...op.claim.meta, keyVersion: Number.MAX_SAFE_INTEGER },
    })
    expect((await peer.apply([tombstone])).parked).toEqual([tombstone])
    const unsafe = await resign(owner, tombstone, {
      meta: { ...op.claim.meta, keyVersion: 2 ** 53 },
    })
    expect(reasons(await peer.apply([unsafe]))).toEqual(['unauthorized'])
    const { branchID: _label, branchRecordID: _record, ...meta } = op.claim.meta
    const bareDelete = await resign(owner, entry, { payload: null, meta })
    expect((await peer.apply([bareDelete])).applied).toBe(1)
  })

  test('wrapping LWW and authenticated candidate retention use the real apply decisions', async () => {
    const owner = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner)
    await peer.apply([source.key, source.branch])
    const first = await dependent(owner, source, 'vault.wrapping')
    const next = await dependent(owner, source, 'vault.wrapping', { counter: 120 })
    await peer.apply([next, first])
    expect((await peer.store.get(first))?.copies[0]?.opHash).toBe(next.opHash)
    const winner = await dependent(owner, source, 'vault.entry', { contentCounter: 95 })
    const loser = await dependent(owner, source, 'vault.entry', { contentCounter: 90 })
    const refused = await dependent(randomIdentity(), source, 'vault.entry', { contentCounter: 99 })
    await peer.apply([winner, loser, refused], {
      authority: { authorize: async (r) => r.issuer === owner.id },
    })
    expect((await peer.store.get(winner))?.copies[0]?.opHash).toBe(winner.opHash)
    expect(peer.candidates().map((r) => r.opHash)).toEqual([winner.opHash, loser.opHash])
    const tampered = { ...loser, payload: fromUTF('{}') }
    expect(reasons(await peer.apply([tampered]))).toEqual(['unauthorized'])
    expect(peer.candidates()).toHaveLength(2)
  })

  test('entry identifiers and opaque consumer fields impose no application writer policy', async () => {
    const owner = randomIdentity()
    const writer = randomIdentity()
    const peer = memoryStore()
    const source = await chain(owner)
    await peer.apply([source.key, source.branch])
    const entry = await dependent(writer, source, 'vault.entry', {
      id: 'consumer:reserved:entry',
      consumer: { arbitrary: { rule: true } },
    })
    expect((await peer.apply([entry])).applied).toBe(1)
    const op = await verified(entry)
    const extra = await resign(writer, entry, {
      meta: { ...op.claim.meta, applicationField: true },
    })
    expect(reasons(await peer.apply([extra]))).toEqual(['unauthorized'])
  })
})

describe('revocation, visibility and key locks', () => {
  test.each(['recipient', 'factor'] as const)(
    'permanent denial inspects the %s address and keeps the revocation signed',
    async (field) => {
      const owner = randomIdentity()
      const recipient = randomIdentity()
      const peer = memoryStore()
      const source = await chain(owner)
      await peer.apply([source.key, source.branch])
      const wrapping = await dependent(owner, source, 'vault.wrapping', {
        recipient: field === 'recipient' ? recipient.id : null,
        factorRecipient: recipient.id,
      })
      await peer.apply([wrapping])
      const revoke = await signed(owner, {
        type: 'vault.revocation',
        id: vaultRevocationRecordID(source.keyID, recipient.id),
        owner: owner.id,
        hlc: stamp(200),
        payload: encodeVaultRecordPayload('vault.revocation', {}),
        meta: { keyID: source.keyID, revokedDID: recipient.id, consumer: {} },
      })
      expect((await peer.apply([revoke])).applied).toBe(1)
      expect(peer.effects()).toEqual([
        { ownerDID: owner.id, keyID: source.keyID },
        { ownerDID: owner.id, keyID: source.keyID },
      ])
      const later = await resign(owner, wrapping, { hlc: stamp(300) })
      expect(reasons(await peer.apply([later]))).toEqual(['unauthorized'])
      const undo = await resign(owner, revoke, { payload: null, hlc: stamp(400) })
      expect(reasons(await peer.apply([undo]))).toEqual(['unauthorized'])
      expect((await peer.store.get(revoke))?.copies[0]?.opHash).toBe(revoke.opHash)
      const fresh = memoryStore()
      expect(reasons(await fresh.apply([undo]))).toEqual(['unauthorized'])
      const context = visibility(peer.store)
      // Visibility uses a transaction-bound port too.
      await peer.store.transaction(async (tx) => {
        expect(
          await definition('vault.wrapping', peer).visibleTo?.(wrapping, { ...context, store: tx }),
        ).toBe(false)
      })
    },
  )

  test('every generic type and previous key association share one owner-qualified lock namespace', async () => {
    const owner = randomIdentity()
    const source = await chain(owner)
    const peer = memoryStore()
    const entry = await dependent(owner, source, 'vault.entry')
    const wrapping = await dependent(owner, source, 'vault.wrapping')
    const revoke = await signed(owner, {
      type: 'vault.revocation',
      id: vaultRevocationRecordID(source.keyID, owner.id),
      owner: owner.id,
      hlc: stamp(200),
      payload: encodeVaultRecordPayload('vault.revocation', {}),
      meta: { keyID: source.keyID, revokedDID: owner.id, consumer: {} },
    })
    const want = [{ type: 'vault.key', key: JSON.stringify([owner.id, source.keyID]) }]
    for (const record of [source.key, source.branch, entry, wrapping, revoke])
      expect(await definition(record.type, peer).lockKeys?.(record, null)).toEqual(want)
    const another = await chain(owner, { version: 2 })
    const secondID = (await chain(randomIdentity())).keyID
    const op = await verified(entry)
    const moved = await resign(owner, entry, { meta: { ...op.claim.meta, keyID: secondID } })
    await peer.apply([source.key, source.branch, entry])
    const previous = await peer.store.get(entry)
    expect(await definition('vault.entry', peer).lockKeys?.(moved, previous)).toEqual([
      { type: 'vault.key', key: JSON.stringify([owner.id, secondID]) },
      ...want,
    ])
    expect(
      await definition('vault.key', peer).lockKeys?.({ ...another.key, opHash: 'forged' }, null),
    ).toEqual([])
  })

  test('disclosure calls read authority with signer and requesting principal kept separate', async () => {
    const owner = randomIdentity()
    const requester = randomIdentity()
    const source = await chain(owner)
    const peer = memoryStore()
    const context = { requester: requester.id }
    const types = vaultRecordTypes({
      ...peer.hooks,
      opKind: OP_KIND,
      authority: {
        async authorize(request) {
          expect(request.verb).toBe('read')
          expect(request.issuer).toBe(owner.id)
          expect(request.transportContext).toBe(context)
          return false
        },
      },
    })
    expect(
      await types
        .get('vault.key')
        ?.visibleTo?.(source.key, { ...visibility(peer.store), transportContext: context }),
    ).toBe(false)
  })
})

function visibility(store: ReturnType<typeof memoryStore>['store']): VisibilityContext {
  return {
    store,
    opKind: OP_KIND,
    requester: { peerDID: randomIdentity().id, controllerDID: null },
    proofs: [],
    authorizeProof: async () => false,
    currentKeyVersion: async () => null,
    isGroupMember: async () => false,
    holderTypes: new Map(),
  }
}

test('a mismatched apply engine cannot cross the definition replay domain or bypass locks', async () => {
  const { applyRecordChunk, verifySignedRecord } = await import('@kokuin/records')
  const owner = randomIdentity()
  const source = await chain(owner)
  const peer = memoryStore()
  const foreignKind = 'other/vault-op'
  const foreign = await resign(owner, source.key, {}, foreignKind)
  const types = vaultRecordTypes({ ...peer.hooks, opKind: OP_KIND })
  const op = await verifySignedRecord(foreign, foreignKind)
  if (op === null) throw new Error('Foreign domain fixture')
  expect(
    await types.get('vault.key')?.authorize(op, {
      record: foreign,
      stored: null,
      store: peer.store,
      resolveController: async () => null,
      verifyCapability: async () => false,
    }),
  ).toBe(false)
  const result = await applyRecordChunk({
    opKind: foreignKind,
    records: [foreign],
    types,
    store: peer.store,
    nowMS: Date.parse('2026-10-24T12:00:00.000Z'),
    maxDriftMS: 60_000,
    receiveClock: () => {},
    resolveController: async () => null,
    verifyCapability: async () => false,
  })
  expect(reasons(result)).toEqual(['unauthorized'])
  expect(await peer.store.get(foreign)).toBeNull()
  const matching = vaultRecordTypes({ ...peer.hooks, opKind: foreignKind })
  expect(
    await matching.get('vault.key')?.authorize(op, {
      record: foreign,
      stored: null,
      store: peer.store,
      resolveController: async () => null,
      verifyCapability: async () => false,
    }),
  ).toBe(true)
})

test('a throwing effect rolls back selected records, retained candidates and earlier effects', async () => {
  const owner = randomIdentity()
  const source = await chain(owner)
  const peer = memoryStore()
  await peer.apply([source.key, source.branch])
  const wrapping = await dependent(owner, source, 'vault.wrapping')
  const entry = await dependent(owner, source, 'vault.entry')
  const failure = new Error('Candidate storage unavailable')
  await expect(
    peer.apply([wrapping, entry], {
      portsFor(store) {
        const ports = peer.hooks.portsFor(store)
        return {
          ...ports,
          async retainEntryCandidate(record) {
            await ports.retainEntryCandidate(record)
            throw failure
          },
        }
      },
    }),
  ).rejects.toBe(failure)
  expect(await peer.store.get(wrapping)).toBeNull()
  expect(await peer.store.get(entry)).toBeNull()
  expect(peer.candidates()).toEqual([])
  expect(peer.effects()).toEqual([])
  expect((await peer.store.get(source.key))?.copies[0]?.opHash).toBe(source.key.opHash)
})

test('two independent apply engines converge by exchanging selected signed records', async () => {
  const owner = randomIdentity()
  const left = memoryStore()
  const right = memoryStore()
  const one = await chain(owner, { counter: 400 })
  const two = await chain(owner, { version: 2, counter: 20 })
  const wrapping = await dependent(owner, one, 'vault.wrapping')
  const laterWrapping = await dependent(owner, two, 'vault.wrapping', { counter: 120 })
  const entry = await dependent(owner, two, 'vault.entry', { contentCounter: 90 })
  const gone = await dependent(owner, one, 'vault.entry', {
    counter: 130,
    contentCounter: 95,
    deleted: true,
  })
  await left.apply([one.key, one.branch, wrapping, gone])
  await right.apply([two.key, two.branch, laterWrapping, entry])
  const types = [
    'vault.key',
    'vault.key-branch',
    'vault.wrapping',
    'vault.entry',
    'vault.revocation',
  ]
  const fromLeft = (await left.store.list(types)).flatMap((d) => d.copies)
  expect((await right.apply(structuredClone(fromLeft))).rejected).toEqual([])
  const fromRight = (await right.store.list(types)).flatMap((d) => d.copies)
  expect((await left.apply(structuredClone(fromRight))).rejected).toEqual([])
  for (const peer of [left, right]) {
    expect((await peer.store.get(one.key))?.copies[0]?.opHash).toBe(two.key.opHash)
    expect((await peer.store.get(wrapping))?.copies[0]?.opHash).toBe(laterWrapping.opHash)
    expect((await peer.store.get(entry))?.copies[0]?.opHash).toBe(gone.opHash)
    expect(await peer.store.list(['vault.key-branch'])).toHaveLength(2)
  }
})

test('requester-owned wrapping proofs earn key and entry visibility without receiver binding', async () => {
  const owner = randomIdentity()
  const holder = randomIdentity()
  const receiver = randomIdentity()
  const peer = memoryStore()
  const source = await chain(owner)
  const entry = await dependent(owner, source, 'vault.entry')
  const proof = await dependent(owner, source, 'vault.wrapping', {
    recipient: holder.id,
    factorRecipient: holder.id,
  })
  const otherOwner = randomIdentity()
  const other = await chain(otherOwner)
  await peer.apply([source.key, source.branch, entry, other.key, other.branch])
  await peer.store.transaction(async (store) => {
    const transportContext = { receiver: receiver.id, requester: holder.id }
    let ctx: VisibilityContext
    let disclosureContext: VisibilityContext
    const params = {
      ...peer.hooks,
      opKind: OP_KIND,
      authority: {
        async authorize(request: CredentialAuthorityRequest) {
          expect(request.transportContext).toBe(transportContext)
          if (request.verb === 'administer') return request.issuer === request.owner
          if (request.op.claim.type === 'vault.wrapping')
            return request.op.claim.meta.recipient === receiver.id
          return await visibleTo(request.record, ['keyHolder'], disclosureContext)
        },
      },
    }
    const types = vaultRecordTypes(params)
    const wrapping = types.get('vault.wrapping')
    if (!wrapping) throw new Error('Missing wrapping definition')
    ctx = {
      ...visibility(store),
      store,
      transportContext,
      requester: { peerDID: holder.id, controllerDID: null },
      proofs: [proof],
      holderTypes: vaultHolderTypes(types),
      currentKeyVersion: vaultKeyVersionReader(store, params),
      authorizeProof: vaultProofAuthorizer(params, store, transportContext),
    }
    disclosureContext = ctx
    expect(
      await wrapping.authorize(await verified(proof), {
        record: proof,
        stored: null,
        store,
        transportContext,
        resolveController: async () => null,
        verifyCapability: async () => false,
      }),
    ).toBe(false)
    const foreignProof = await dependent(otherOwner, other, 'vault.wrapping', {
      recipient: holder.id,
    })
    const nonWrapping = await resign(owner, entry, {
      meta: { ...(await verified(entry)).claim.meta, recipient: holder.id },
    })
    for (const invalid of [nonWrapping]) {
      const rejected = { ...ctx, proofs: [invalid] }
      disclosureContext = rejected
      expect(await verifyHolderProof(invalid, rejected)).toBe(false)
      expect(await types.get('vault.key')?.visibleTo?.(source.key, rejected)).toBe(false)
      expect(await types.get('vault.entry')?.visibleTo?.(entry, rejected)).toBe(false)
    }
    const foreignContext = { ...ctx, proofs: [foreignProof] }
    disclosureContext = foreignContext
    expect(await verifyHolderProof(foreignProof, foreignContext)).toBe(true)
    expect(await types.get('vault.key')?.visibleTo?.(source.key, foreignContext)).toBe(false)
    expect(await types.get('vault.entry')?.visibleTo?.(entry, foreignContext)).toBe(false)
    expect([...ctx.holderTypes.keys()]).toEqual(['vault.wrapping'])
    expect(vaultHolderTypes(new Map()).size).toBe(0)
    expect(await ctx.currentKeyVersion(owner.id, source.keyID)).toBe(1)
    expect(await ctx.currentKeyVersion(otherOwner.id, source.keyID)).toBeNull()
    expect(
      await vaultKeyVersionReader(store, { opKind: 'other/vault-op' })(owner.id, source.keyID),
    ).toBeNull()
    for (const refusal of [
      { authority: { authorize: async () => false } },
      { validateConsumerMetadata: async () => false },
      { opKind: 'other/vault-op' },
    ]) {
      const refused = {
        ...ctx,
        authorizeProof: vaultProofAuthorizer({ ...params, ...refusal }, store, transportContext),
      }
      disclosureContext = refused
      expect(await verifyHolderProof(proof, refused)).toBe(false)
      expect(await types.get('vault.key')?.visibleTo?.(source.key, refused)).toBe(false)
      expect(await types.get('vault.entry')?.visibleTo?.(entry, refused)).toBe(false)
    }
    expect(await ctx.authorizeProof(nonWrapping, null)).toBe(false)
    disclosureContext = ctx
    expect(await verifyHolderProof(proof, ctx)).toBe(true)
    expect(await types.get('vault.key')?.visibleTo?.(source.key, ctx)).toBe(true)
    expect(await types.get('vault.entry')?.visibleTo?.(entry, ctx)).toBe(true)
    const rotated = await chain(owner, { version: 2 })
    await store.putCopy(rotated.key)
    const stale = ctx
    disclosureContext = stale
    expect(await verifyHolderProof(proof, stale)).toBe(false)
    expect(await types.get('vault.key')?.visibleTo?.(source.key, stale)).toBe(false)
    expect(await types.get('vault.entry')?.visibleTo?.(entry, stale)).toBe(false)
  })
})
