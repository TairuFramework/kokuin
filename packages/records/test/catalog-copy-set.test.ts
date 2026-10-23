import { normalizeDID, randomIdentity, type SigningIdentity } from '@kokuin/token'
import { blake3 } from '@noble/hashes/blake3.js'
import { toB64U } from '@sozai/codec'
import { HLC } from '@sozai/hlc'
import { describe, expect, test } from 'vitest'

import * as records from '../src/index.js'
import {
  type ApplyRecordChunkParams,
  applyRecordChunk,
  canonicalRecordClaim,
  fingerprintRange,
  nextRequesterSteps,
  type RecordClaim,
  RecordContentRefusalError,
  type RecordDecision,
  type RecordKey,
  type RecordStoreAdapter,
  type RecordTypeDefinition,
  rangeLeaf,
  recordPayloadDigest,
  type SignedRecord,
  signRecordOp,
  splitRange,
  summarizeRange,
  type VerifiedRecordOp,
  type VisibilityContext,
  verifyHolderProof,
  verifySignedRecord,
} from '../src/index.js'

const NOW = Date.now()
const TYPE = 'catalog'
const LWW = { kind: 'lww' } as const

function keyOf(record: RecordKey): string {
  return JSON.stringify([record.type, record.owner, record.id])
}

function stamp(signer: SigningIdentity, offset = 0): string {
  return HLC.serialize({ wallTime: NOW + offset, counter: 0, nodeID: signer.id })
}

async function signed(
  signer: SigningIdentity,
  key: RecordKey,
  options: {
    hlc?: string
    payload?: Uint8Array | null
    meta?: Record<string, unknown>
  } = {},
): Promise<SignedRecord> {
  const payload = options.payload === undefined ? new Uint8Array([1]) : options.payload
  const claim: RecordClaim = {
    ...key,
    hlc: options.hlc ?? stamp(signer),
    payloadDigest: recordPayloadDigest(payload),
    deleted: payload === null,
    meta: options.meta ?? {},
  }
  return { ...key, hlc: claim.hlc, payload, ...(await signRecordOp(signer, claim)) }
}

async function decisionFor(record: SignedRecord): Promise<RecordDecision> {
  const op = await verifySignedRecord(record)
  if (op === null) throw new Error('The signed fixture did not verify')
  return {
    key: { type: record.type, owner: record.owner, id: record.id },
    decisionHLC: typeof op.claim.meta.version === 'string' ? op.claim.meta.version : op.claim.hlc,
    contentDigest:
      typeof records.recordDecisionDigest === 'function'
        ? await records.recordDecisionDigest(record)
        : toB64U(blake3(canonicalRecordClaim(op.claim), { dkLen: 32 })),
    copies: [record],
  }
}

function memoryStore(initial: ReadonlyArray<RecordDecision> = []) {
  let rows = new Map(initial.map((decision) => [keyOf(decision.key), decision]))
  const copyWrites: Array<SignedRecord> = []
  const pruned: Array<{ key: RecordKey; signerDID: string }> = []

  const adapterOver = (view: () => Map<string, RecordDecision>) => {
    const adapter = {
      transaction: async <R>(fn: (tx: RecordStoreAdapter) => Promise<R>): Promise<R> =>
        await fn(adapter as unknown as RecordStoreAdapter),
      get: async (keyOrType: RecordKey | string, id?: string) => {
        if (typeof keyOrType === 'string') {
          return (
            [...view().values()].find(
              (decision) => decision.key.type === keyOrType && decision.key.id === id,
            )?.copies[0] ?? null
          )
        }
        return view().get(keyOf(keyOrType)) ?? null
      },
      list: async (types: ReadonlyArray<string>) =>
        [...view().values()].filter((decision) => types.includes(decision.key.type)),
      put: async (record: SignedRecord) => {
        view().set(keyOf(record), await decisionFor(record))
      },
      putCopy: async (record: SignedRecord) => {
        copyWrites.push(record)
        const next = await decisionFor(record)
        const previous = view().get(keyOf(next.key))
        view().set(keyOf(next.key), {
          ...next,
          copies:
            previous?.contentDigest === next.contentDigest &&
            previous.decisionHLC === next.decisionHLC
              ? [...previous.copies.filter((copy) => copy.opHash !== record.opHash), record]
              : [record],
        })
      },
      pruneCopy: async (key: RecordKey, signerDID: string) => {
        pruned.push({ key, signerDID })
        const decision = view().get(keyOf(key))
        if (decision === undefined) return
        const copies: Array<SignedRecord> = []
        for (const copy of decision.copies) {
          const op = await verifySignedRecord(copy)
          if (op?.issuer !== signerDID) copies.push(copy)
        }
        view().set(keyOf(key), { ...decision, copies })
      },
    }
    return adapter
  }
  const store = {
    ...adapterOver(() => rows),
    transaction: async <R>(fn: (tx: RecordStoreAdapter) => Promise<R>): Promise<R> => {
      const draft = new Map(rows)
      const result = await fn(adapterOver(() => draft) as unknown as RecordStoreAdapter)
      rows = draft
      return result
    },
  }
  const read = (key: RecordKey): RecordDecision | null => rows.get(keyOf(key)) ?? null
  const restart = () => memoryStore([...rows.values()])
  return { store: store as unknown as RecordStoreAdapter, read, restart, copyWrites, pruned }
}

function definition(overrides: Partial<RecordTypeDefinition> = {}): RecordTypeDefinition {
  return {
    type: TYPE,
    policy: LWW,
    dependsOn: [],
    authorize: async (op, ctx) =>
      op.issuer === op.claim.owner || (await ctx.resolveController(op.issuer)) === op.claim.owner,
    dependencies: () => [],
    ...overrides,
  }
}

function applyWith(
  input: ReadonlyArray<SignedRecord>,
  store: RecordStoreAdapter,
  types: ReadonlyArray<RecordTypeDefinition> = [definition()],
  overrides: Partial<ApplyRecordChunkParams> = {},
) {
  return applyRecordChunk({
    records: input,
    store,
    types: new Map(types.map((item) => [item.type, item])),
    nowMS: NOW,
    maxDriftMS: 60_000,
    receiveClock: () => {},
    resolveController: async () => null,
    verifyCapability: async () => false,
    ...overrides,
  })
}

describe('owner-qualified decisions and signed copies', () => {
  test('decision reader excludes verified copies with invalid decision stamps', async () => {
    const signer = randomIdentity()
    const key: RecordKey = {
      type: 'catalog.exposure',
      owner: normalizeDID(signer.id),
      id: 'invalid-decision-stamp',
    }
    const invalid = await signed(signer, key, {
      meta: { version: '2026-09-29T12:00:00Z:0:test' },
    })
    const missing = await signed(signer, key)
    const valid = await signed(signer, key, {
      meta: { version: stamp(signer, 1) },
    })
    const invalidOp = await verifySignedRecord(invalid)
    const missingOp = await verifySignedRecord(missing)
    const validOp = await verifySignedRecord(valid)
    if (invalidOp === null || missingOp === null || validOp === null)
      throw new Error('invalid signed fixture')

    expect(
      records.recordDecisionFromVerifiedCopies(key, [{ copy: invalid, op: invalidOp }], 'version'),
    ).toBeNull()
    expect(
      records.recordDecisionFromVerifiedCopies(key, [{ copy: missing, op: missingOp }], 'version'),
    ).toBeNull()
    for (const entries of [
      [
        { copy: invalid, op: invalidOp },
        { copy: valid, op: validOp },
      ],
      [
        { copy: valid, op: validOp },
        { copy: invalid, op: invalidOp },
      ],
    ]) {
      expect(records.recordDecisionFromVerifiedCopies(key, entries, 'version')?.copies).toEqual([
        valid,
      ])
    }
  })

  test('decision reader orders equal-time versions by node before digest', async () => {
    const version = (nodeID: string) => HLC.serialize({ wallTime: NOW, counter: 0, nodeID })
    let pair: {
      key: RecordKey
      high: SignedRecord
      highOp: VerifiedRecordOp
      low: { copy: SignedRecord; op: VerifiedRecordOp }
    } | null = null
    for (let attempt = 0; attempt < 128 && pair === null; attempt++) {
      const signer = randomIdentity()
      const key: RecordKey = {
        type: 'catalog.exposure',
        owner: normalizeDID(signer.id),
        id: 'node-order',
      }
      const high = await signed(signer, key, {
        payload: null,
        meta: { version: version('z') },
      })
      const highOp = await verifySignedRecord(high)
      if (highOp === null) throw new Error('invalid signed fixture')
      for (let index = 0; index < 32; index++) {
        const copy = await signed(signer, key, { meta: { version: version(`a${index}`) } })
        const op = await verifySignedRecord(copy)
        if (op === null) throw new Error('invalid signed fixture')
        if (records.recordClaimDigest(op.claim) > records.recordClaimDigest(highOp.claim)) {
          pair = { key, high, highOp, low: { copy, op } }
          break
        }
      }
    }
    if (pair === null) throw new Error('no opposing digest fixture')
    const { key, high, highOp, low } = pair

    for (const entries of [
      [low, { copy: high, op: highOp }],
      [{ copy: high, op: highOp }, low],
    ]) {
      expect(records.recordDecisionFromVerifiedCopies(key, entries, 'version')?.copies).toEqual([
        high,
      ])
    }
  })

  test('ownerQualifiedRecordsDoNotCollide', async () => {
    const alice = randomIdentity()
    const mallory = randomIdentity()
    const aliceKey: RecordKey = { type: TYPE, owner: normalizeDID(alice.id), id: 'shared' }
    const malloryKey: RecordKey = { ...aliceKey, owner: normalizeDID(mallory.id) }
    const aliceLive = await signed(alice, aliceKey)
    const malloryLive = await signed(mallory, malloryKey)
    const malloryDelete = await signed(mallory, malloryKey, {
      hlc: stamp(mallory, 1),
      payload: null,
    })

    for (const order of [
      [aliceLive, malloryLive],
      [malloryLive, aliceLive],
    ]) {
      const memory = memoryStore()
      expect((await applyWith(order, memory.store)).applied).toBe(2)
      expect(memory.read(aliceKey)?.copies).toEqual([aliceLive])
      expect(memory.read(malloryKey)?.copies).toEqual([malloryLive])
      expect((await applyWith([malloryDelete], memory.store)).applied).toBe(1)
      expect(memory.read(aliceKey)?.copies).toEqual([aliceLive])
      expect(memory.read(malloryKey)?.copies).toEqual([malloryDelete])
      const leaves = [memory.read(aliceKey), memory.read(malloryKey)].map((decision) => {
        const leaf = rangeLeaf(decision as RecordDecision, LWW)
        if (leaf === null) throw new Error('Decision leaf was not produced')
        return leaf
      })
      expect(leaves.map((leaf) => leaf.owner)).toEqual([aliceKey.owner, malloryKey.owner])
      expect(new Set(leaves.map((leaf) => leaf.id)).size).toBe(1)
      const bounds = { type: TYPE, lower: null, upper: null }
      expect(summarizeRange(leaves, bounds).count).toBe(2)
      expect(splitRange(leaves, bounds, 16)).toEqual([
        {
          bounds,
          leaves: [...leaves].sort((left, right) => (left.owner < right.owner ? -1 : 1)),
        },
      ])
    }
  })

  test('dependencyCannotUseAnotherOwnersSameID', async () => {
    const alice = randomIdentity()
    const mallory = randomIdentity()
    const aliceParent: RecordKey = {
      type: 'test.parent',
      owner: normalizeDID(alice.id),
      id: 'same',
    }
    const malloryParent: RecordKey = { ...aliceParent, owner: normalizeDID(mallory.id) }
    const childKey: RecordKey = { type: 'test.child', owner: aliceParent.owner, id: 'child' }
    const child = await signed(alice, childKey, { meta: { parent: 'same' } })
    const parent = await signed(alice, aliceParent)
    const stranger = await signed(mallory, malloryParent)
    const types = [
      definition({ type: aliceParent.type }),
      definition({
        type: childKey.type,
        dependsOn: [aliceParent.type],
        dependencies: (_record, op) => [
          { type: aliceParent.type, owner: op.claim.owner, id: op.claim.meta.parent as string },
        ],
      }),
    ]
    const memory = memoryStore([await decisionFor(stranger)])
    const first = await applyWith([child], memory.store, types)
    expect(first.parked).toEqual([child])
    expect(memory.read(childKey)).toBeNull()
    const second = await applyWith([parent, ...first.parked], memory.store, types)
    expect(second.applied).toBe(2)
    expect(memory.read(childKey)?.copies).toEqual([child])
    expect(memory.read(malloryParent)?.copies).toEqual([stranger])
  })

  test('holderProofCannotUseAnotherOwnersSameID', async () => {
    const alice = randomIdentity()
    const mallory = randomIdentity()
    const reader = randomIdentity()
    const owner = normalizeDID(alice.id)
    const readerDID = normalizeDID(reader.id)
    const branchKey: RecordKey = { type: 'test.branch', owner, id: 'key:3' }
    const wrappingKey: RecordKey = { type: 'test.wrapping', owner, id: 'wrapping' }
    const malloryBranch = await signed(
      mallory,
      { ...branchKey, owner: normalizeDID(mallory.id) },
      {
        meta: { keyVersion: 3 },
      },
    )
    const aliceBranch = await signed(alice, branchKey, { meta: { keyVersion: 3 } })
    const malloryWrapping = await signed(
      mallory,
      { ...wrappingKey, owner: normalizeDID(mallory.id) },
      { meta: { keyID: 'key', keyVersion: 3, recipient: readerDID } },
    )
    const proof = await signed(alice, wrappingKey, {
      meta: { keyID: 'key', keyVersion: 3, recipient: readerDID },
    })
    const wrappingType = definition({
      type: wrappingKey.type,
      dependsOn: [branchKey.type],
      dependencies: (_record, op) => [
        {
          type: branchKey.type,
          owner: op.claim.owner,
          id: 'key:3',
          satisfiedBy: (stored) => stored.claim.meta.keyVersion === 3,
        },
      ],
    })
    const context = (store: RecordStoreAdapter): VisibilityContext => ({
      requester: { peerDID: readerDID, controllerDID: null },
      proofs: [proof],
      store,
      authorizeProof: async () => true,
      currentKeyVersion: async () => 3,
      isGroupMember: async () => false,
      holderTypes: new Map([[wrappingKey.type, wrappingType]]),
    })
    const wrongBranch = memoryStore([await decisionFor(malloryBranch)])
    expect(await verifyHolderProof(proof, context(wrongBranch.store))).toBe(false)
    const wrongWrapping = memoryStore([
      await decisionFor(aliceBranch),
      await decisionFor(malloryWrapping),
    ])
    expect(await verifyHolderProof(proof, context(wrongWrapping.store))).toBe(true)
    const device = randomIdentity()
    const deviceWrapping = await signed(device, wrappingKey, {
      hlc: proof.hlc,
      meta: { keyID: 'key', keyVersion: 3, recipient: readerDID },
    })
    const alternateCopy = memoryStore([
      await decisionFor(aliceBranch),
      await decisionFor(deviceWrapping),
    ])
    expect(await verifyHolderProof(proof, context(alternateCopy.store))).toBe(true)
  })

  test('equalDecisionUsesContentDigestNotSigningTime', async () => {
    const alice = randomIdentity()
    const device = randomIdentity()
    const key: RecordKey = { type: TYPE, owner: normalizeDID(alice.id), id: 'equal' }
    const hlc = stamp(alice)
    const low = await signed(alice, key, { hlc, payload: new Uint8Array([1]) })
    const high = await signed(alice, key, { hlc, payload: new Uint8Array([2]) })
    const resignedHigh = await signed(device, key, { hlc, payload: new Uint8Array([2]) })
    expect(records.recordDecisionDigest).toBeTypeOf('function')
    const lowDigest = await records.recordDecisionDigest(low)
    const highDigest = await records.recordDecisionDigest(high)
    expect(await records.recordDecisionDigest(resignedHigh)).toBe(highDigest)
    const versionedOriginal = await signed(alice, key, { hlc, meta: { version: hlc } })
    const versionedResigned = await signed(device, key, {
      hlc: stamp(device, 1),
      meta: { version: hlc },
    })
    expect(await records.recordDecisionDigest(versionedResigned)).toBe(
      await records.recordDecisionDigest(versionedOriginal),
    )
    expect(lowDigest).not.toBe(highDigest)
    const winner = lowDigest > highDigest ? low : high
    for (const order of [
      [low, high],
      [high, low],
      [low, resignedHigh, high],
    ]) {
      const memory = memoryStore()
      await applyWith(order, memory.store, [definition()], {
        resolveController: async (did) => (did === normalizeDID(device.id) ? key.owner : null),
      })
      expect(memory.read(key)?.contentDigest).toBe(await records.recordDecisionDigest(winner))
    }
  })

  test('a signed versioned claim has a fixed content digest across signing stamps', async () => {
    const signer = randomIdentity()
    const decisionHLC = '2026-09-27T00:00:00.000Z:00000000:node'
    const claim: RecordClaim = {
      type: 'catalog.vector',
      id: 'fixed',
      owner: 'did:key:o',
      hlc: '2026-09-27T00:00:01.000Z:00000000:node',
      payloadDigest: null,
      deleted: true,
      meta: { topic: 'catalog', version: decisionHLC },
    }
    const sign = async (signedClaim: RecordClaim): Promise<SignedRecord> => ({
      type: signedClaim.type,
      id: signedClaim.id,
      owner: signedClaim.owner,
      hlc: signedClaim.hlc,
      payload: null,
      ...(await signRecordOp(signer, signedClaim)),
    })
    const first = await sign(claim)
    const resigned = await sign({
      ...claim,
      hlc: '2026-09-27T00:00:02.000Z:00000000:node',
    })
    expect(first.opHash).not.toBe(resigned.opHash)
    expect(await records.recordDecisionDigest(first)).toBe(
      'uO4S0JWZcbMAIZT8a4gzva2n3XCguybZvIb7GcT2HLw',
    )
    expect(await records.recordDecisionDigest(resigned)).toBe(
      'uO4S0JWZcbMAIZT8a4gzva2n3XCguybZvIb7GcT2HLw',
    )
  })

  test('resignedCopyChangesSignerSetLeaf', async () => {
    const alice = randomIdentity()
    const device = randomIdentity()
    const key: RecordKey = { type: TYPE, owner: normalizeDID(alice.id), id: 'resigned' }
    const hlc = stamp(alice)
    const old = await signed(device, key, { hlc })
    const replacement = await signed(alice, key, { hlc })
    const oldDecision = await decisionFor(old)
    const both: RecordDecision = { ...oldDecision, copies: [old, replacement] }
    expect(() => rangeLeaf(oldDecision, LWW)).not.toThrow()
    const oldLeaf = rangeLeaf(oldDecision, LWW)
    const bothLeaf = rangeLeaf(both, LWW)
    if (oldLeaf === null || bothLeaf === null) throw new Error('Decision leaf was not produced')
    expect(fingerprintRange([oldLeaf])).not.toBe(fingerprintRange([bothLeaf]))
    expect(
      nextRequesterSteps([oldLeaf], {
        bounds: { type: TYPE, lower: null, upper: null },
        leaves: [bothLeaf],
      }),
    ).toEqual([{ get: [key] }])
    const memory = memoryStore([oldDecision])
    await applyWith([old, replacement], memory.store, [definition()], {
      resolveController: async (did) => (did === normalizeDID(device.id) ? key.owner : null),
    })
    expect(
      memory
        .read(key)
        ?.copies.map((copy) => copy.opHash)
        .sort(),
    ).toEqual([old.opHash, replacement.opHash].sort())
    expect(memory.copyWrites.map((copy) => copy.opHash)).toEqual([replacement.opHash])
  })

  test('oldCopyPrunedOnlyAfterReplacement', async () => {
    const alice = randomIdentity()
    const device = randomIdentity()
    const key: RecordKey = { type: TYPE, owner: normalizeDID(alice.id), id: 'recover' }
    const hlc = stamp(alice)
    const old = await signed(device, key, { hlc })
    const replacement = await signed(alice, key, { hlc })
    const memory = memoryStore([await decisionFor(old)])
    expect(memory.restart().read(key)?.copies).toEqual([old])
    expect(memory.pruned).toEqual([])
    await applyWith([replacement], memory.store, [definition()], {
      resolveController: async () => null,
    })
    expect(memory.read(key)?.copies).toEqual([replacement])
    expect(memory.restart().read(key)?.copies).toEqual([replacement])
    expect(memory.pruned).toEqual([{ key, signerDID: normalizeDID(device.id) }])
  })

  test('statelessContentRefusalRejectsOnlyTheRefusedRecord', async () => {
    const signer = randomIdentity()
    const key = { type: TYPE, owner: normalizeDID(signer.id), id: 'refused' }
    const bad = await signed(signer, key)
    const good = await signed(signer, { ...key, id: 'good' })
    const memory = memoryStore()
    const refusal = new RecordContentRefusalError('invalid content')
    const type = definition({
      precheck: async (_op, record) => {
        if (record.id === bad.id) throw refusal
        return true
      },
    })
    const result = await applyWith([bad, good], memory.store, [type])
    expect(result.rejected).toEqual([{ record: bad, reason: 'content-refused' }])
    expect(result.applied).toBe(1)
    expect(memory.read(key)).toBeNull()
    expect(memory.read({ ...key, id: 'good' })?.copies).toEqual([good])
    memory.store.isTransaction = true
    await expect(applyWith([bad], memory.store, [type])).rejects.toBe(refusal)
  })

  test('recordFaultDoesNotQuarantine', async () => {
    const alice = randomIdentity()
    const key: RecordKey = { type: TYPE, owner: normalizeDID(alice.id), id: 'fault' }
    const bad = await signed(alice, key)
    const good = await signed(alice, { ...key, id: 'good' })
    const resolverError = new Error('controller unavailable')
    await expect(
      applyWith(
        [bad],
        memoryStore().store,
        [
          definition({
            authorize: async (_op, ctx) => {
              await ctx.resolveController('device')
              return true
            },
          }),
        ],
        {
          resolveController: async () => {
            throw resolverError
          },
        },
      ),
    ).rejects.toBe(resolverError)
    const storeError = new Error('store unavailable')
    const faulty = memoryStore()
    faulty.store.transaction = async () => {
      throw storeError
    }
    await expect(applyWith([bad], faulty.store)).rejects.toBe(storeError)
    const hookError = new Error('hook unavailable')
    await expect(
      applyWith([bad], memoryStore().store, [
        definition({
          afterApply: async () => {
            throw hookError
          },
        }),
      ]),
    ).rejects.toBe(hookError)

    const memory = memoryStore()
    const result = await applyWith([bad, good], memory.store, [
      definition({
        afterApply: async (record) => {
          if (record.id === bad.id) throw new RecordContentRefusalError('bad content')
        },
      }),
    ])
    expect(result.rejected.map(({ record }) => record)).toEqual([bad])
    expect(result.applied).toBe(1)
    expect(memory.read(key)).toBeNull()
    expect(memory.read({ ...key, id: 'good' })?.copies).toEqual([good])
  })
})
