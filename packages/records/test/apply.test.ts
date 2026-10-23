import type * as TokenModule from '@kokuin/token'
import {
  createIdentity,
  normalizeDID,
  randomIdentity,
  type SigningIdentity,
  stringifyToken,
  verifyToken,
} from '@kokuin/token'
import { blake3 } from '@noble/hashes/blake3.js'
import { canonicalStringify, fromUTF, toB64U } from '@sozai/codec'
import { HLC, type HLCTimestamp } from '@sozai/hlc'
import { beforeEach, describe, expect, test, vi } from 'vitest'

import {
  type ApplyRecordChunkParams,
  applyRecordChunk,
  MAX_RECORD_ID_LENGTH,
  type RecordAuthorizeContext,
  type RecordClaim,
  RecordSourceChangedError,
  type RecordStoreAdapter,
  type RecordTypeDefinition,
  RecordTypeGraphError,
  recordDecisionDigest,
  recordPayloadDigest,
  type SignedRecord,
  signRecordOp,
  type VerifiedRecordOp,
  verifyRecordOp,
} from '../src/index.js'
import { decisionOf } from './decision-fixture.js'

// Pass-through spy on token verification, so a test can prove the signature check never ran.
vi.mock('@kokuin/token', async (importOriginal) => {
  const actual = await importOriginal<typeof TokenModule>()
  return { ...actual, verifyToken: vi.fn(actual.verifyToken) }
})

type TestIdentity = SigningIdentity

const NOW = Date.now()
const MAX_DRIFT_MS = 60_000
const DAY_MS = 24 * 60 * 60 * 1000

beforeEach(() => {
  vi.mocked(verifyToken).mockClear()
})

function rowKey(type: string, owner: string, id: string): string {
  return JSON.stringify([type, owner, id])
}

/**
 * A store whose transaction works on a copy and swaps it in on success, so a throw rolls
 * the whole chunk back. `writes` records every `put`, committed or not.
 */
function memoryStore(initial: ReadonlyArray<SignedRecord> = []) {
  let rows = new Map(
    initial.map((record) => [rowKey(record.type, record.owner, record.id), record]),
  )
  const writes: Array<SignedRecord> = []
  const over = (view: () => Map<string, SignedRecord>): RecordStoreAdapter => {
    const adapter: RecordStoreAdapter = {
      transaction: async (fn) => await fn(adapter),
      get: async (key) => {
        const record = view().get(rowKey(key.type, key.owner, key.id))
        return record?.owner === key.owner ? decisionOf(record) : null
      },
      list: async (types) =>
        [...view().values()].filter((record) => types.includes(record.type)).map(decisionOf),
      putCopy: async (record) => {
        writes.push(record)
        view().set(rowKey(record.type, record.owner, record.id), record)
      },
      pruneCopy: async () => {},
    }
    return adapter
  }
  const store: RecordStoreAdapter = {
    ...over(() => rows),
    transaction: async (fn) => {
      const draft = new Map(rows)
      const result = await fn(over(() => draft))
      rows = draft
      return result
    },
  }
  const read = (type: string, id: string, owner?: string): SignedRecord | null =>
    [...rows.values()].find(
      (record) =>
        record.type === type && record.id === id && (owner === undefined || record.owner === owner),
    ) ?? null
  return { store, writes, read }
}

type Draft = {
  type?: string
  id?: string
  owner?: string
  offsetMS?: number
  counter?: number
  hlc?: string
  payload?: Uint8Array | null
  meta?: Record<string, unknown>
}

function claimFor(identity: TestIdentity, draft: Draft = {}): RecordClaim {
  const payload = draft.payload === undefined ? new Uint8Array([1]) : draft.payload
  return {
    type: draft.type ?? 'test.value',
    id: draft.id ?? 'one',
    owner: draft.owner ?? normalizeDID(identity.id),
    hlc:
      draft.hlc ??
      HLC.serialize({
        wallTime: NOW + (draft.offsetMS ?? 0),
        counter: draft.counter ?? 0,
        nodeID: identity.id,
      }),
    payloadDigest: recordPayloadDigest(payload),
    deleted: payload === null,
    meta: draft.meta ?? {},
  }
}

async function makeRecord(identity: TestIdentity, draft: Draft = {}): Promise<SignedRecord> {
  const claim = claimFor(identity, draft)
  const signed = await signRecordOp(identity, claim)
  const payload = draft.payload === undefined ? new Uint8Array([1]) : draft.payload
  return { type: claim.type, id: claim.id, owner: claim.owner, hlc: claim.hlc, payload, ...signed }
}

/**
 * The owner-binding rule every type follows: the stored owner (or, on a first
 * write, the claimed one) wrote it, a device acting for it through its controller did, or the
 * op carries a capability chain from it.
 */
async function ownerBinding(op: VerifiedRecordOp, ctx: RecordAuthorizeContext): Promise<boolean> {
  const owner = ctx.stored?.owner ?? op.claim.owner
  if (op.issuer === owner || (await ctx.resolveController(op.issuer)) === owner) {
    return true
  }
  const tokens = op.claim.meta.capability
  return (
    Array.isArray(tokens) &&
    tokens.every((token) => typeof token === 'string') &&
    (await ctx.verifyCapability(tokens, owner, op.issuer))
  )
}

function valueType(overrides: Partial<RecordTypeDefinition> = {}): RecordTypeDefinition {
  return {
    type: 'test.value',
    policy: { kind: 'lww' },
    dependsOn: [],
    authorize: ownerBinding,
    dependencies: () => [],
    ...overrides,
  }
}

function typesOf(...definitions: Array<RecordTypeDefinition>) {
  return new Map(definitions.map((definition) => [definition.type, definition]))
}

function applyWith(
  records: ReadonlyArray<SignedRecord>,
  store: RecordStoreAdapter,
  types: ReadonlyMap<string, RecordTypeDefinition>,
  params: Partial<ApplyRecordChunkParams> = {},
) {
  return applyRecordChunk({
    records,
    store,
    types,
    nowMS: NOW,
    maxDriftMS: MAX_DRIFT_MS,
    receiveClock: () => {},
    resolveController: async () => null,
    verifyCapability: async () => false,
    ...params,
  })
}

test('same-decision chunk verifies 64 incoming signers at most twice each', async () => {
  const owner = randomIdentity()
  const claim = claimFor(owner)
  const copies = await Promise.all(
    Array.from({ length: 64 }, async () => {
      const signer = randomIdentity()
      return {
        type: claim.type,
        id: claim.id,
        owner: claim.owner,
        hlc: claim.hlc,
        payload: new Uint8Array([1]),
        ...(await signRecordOp(signer, claim)),
      }
    }),
  )
  let held: Array<SignedRecord> = []
  const store: RecordStoreAdapter = {
    transaction: async (fn) => await fn(store),
    get: async () =>
      held.length === 0 ? null : { ...decisionOf(held[0] as SignedRecord), copies: held },
    list: async () => [],
    putCopy: async (record) => {
      held = [...held, record]
    },
    pruneCopy: async () => {},
  }
  vi.mocked(verifyToken).mockClear()
  const result = await applyWith(copies, store, typesOf(valueType({ authorize: async () => true })))
  expect(result.applied).toBe(64)
  expect(held).toHaveLength(64)
  expect(vi.mocked(verifyToken).mock.calls.length).toBeLessThanOrEqual(128)
})

const VERSIONED = {
  kind: 'monotonic' as const,
  version: (claim: RecordClaim) => claim.meta.version as ReadonlyArray<number>,
}

describe('the clock gate runs before anything else', () => {
  test('future stamp is rejected before any receiver side effect', async () => {
    const identity = randomIdentity()
    const nowMS = Date.now()
    const claim: RecordClaim = {
      type: 'test.value',
      id: 'one',
      owner: normalizeDID(identity.id),
      hlc: HLC.serialize({ wallTime: nowMS + 60_001, counter: 0, nodeID: identity.id }),
      payloadDigest: recordPayloadDigest(new Uint8Array([1])),
      deleted: false,
      meta: {},
    }
    const signed = await signRecordOp(identity, claim)
    const put = vi.fn(async () => {})
    const receiveClock = vi.fn()
    const authorize = vi.fn(async () => true)
    const store: RecordStoreAdapter = {
      transaction: async (fn) => await fn(store),
      get: async () => null,
      list: async () => [],
      putCopy: put,
      pruneCopy: async () => {},
    }
    const types = new Map([
      [
        'test.value',
        {
          type: 'test.value',
          policy: { kind: 'lww' as const },
          dependsOn: [],
          authorize,
          dependencies: () => [],
        },
      ],
    ])
    const result = await applyRecordChunk({
      records: [
        {
          type: claim.type,
          id: claim.id,
          owner: claim.owner,
          hlc: claim.hlc,
          payload: new Uint8Array([1]),
          ...signed,
        },
      ],
      store,
      types,
      nowMS,
      maxDriftMS: 60_000,
      receiveClock,
      resolveController: async () => null,
      verifyCapability: async () => false,
    })
    expect(result.rejected[0]?.reason).toBe('clock')
    expect(authorize).not.toHaveBeenCalled()
    expect(put).not.toHaveBeenCalled()
    expect(receiveClock).not.toHaveBeenCalled()
  })

  const cases: Array<[string, (identity: TestIdentity) => Draft]> = [
    ['a canonical stamp past the drift bound', () => ({ offsetMS: MAX_DRIFT_MS + 1 })],
    [
      'an unpadded counter',
      (identity) => ({ hlc: `${new Date(NOW).toISOString()}:1:${identity.id}` }),
    ],
    ['a stamp that does not parse', () => ({ hlc: 'not-a-stamp' })],
  ]

  test.each(cases)('%s never reaches the signature, store, policy or clock', async (_, draft) => {
    const identity = randomIdentity()
    const record = await makeRecord(identity, { ...draft(identity), meta: { version: [1] } })
    const get = vi.fn(async () => null)
    const put = vi.fn(async () => {})
    const store: RecordStoreAdapter = {
      transaction: async (fn) => await fn(store),
      get,
      list: async () => [],
      putCopy: put,
      pruneCopy: async () => {},
    }
    const version = vi.fn(VERSIONED.version)
    const authorize = vi.fn(async () => true)
    const dependencies = vi.fn(() => [])
    const receiveClock = vi.fn()
    const result = await applyWith(
      [record],
      store,
      typesOf(valueType({ policy: { kind: 'monotonic', version }, authorize, dependencies })),
      { receiveClock },
    )
    expect(result).toEqual({
      applied: 0,
      parked: [],
      rejected: [{ record, reason: 'clock' }],
      conflicts: [],
    })
    expect(verifyToken).not.toHaveBeenCalled()
    expect(get).not.toHaveBeenCalled()
    expect(dependencies).not.toHaveBeenCalled()
    expect(authorize).not.toHaveBeenCalled()
    expect(version).not.toHaveBeenCalled()
    expect(put).not.toHaveBeenCalled()
    expect(receiveClock).not.toHaveBeenCalled()
  })

  test('the past is unbounded: a week-old write still applies', async () => {
    const identity = randomIdentity()
    const { store, read } = memoryStore()
    const record = await makeRecord(identity, { offsetMS: -7 * DAY_MS })
    const result = await applyWith([record], store, typesOf(valueType()))
    expect(result.applied).toBe(1)
    expect(read('test.value', 'one')).toEqual(record)
  })

  test('a bounded envelope stamp cannot carry a far-future signed stamp', async () => {
    const identity = randomIdentity()
    const future = await makeRecord(identity, { offsetMS: 10 * DAY_MS })
    const disguised = { ...future, hlc: claimFor(identity).hlc }
    const { store, writes } = memoryStore()
    const authorize = vi.fn(async () => true)
    const receiveClock = vi.fn()
    const result = await applyWith([disguised], store, typesOf(valueType({ authorize })), {
      receiveClock,
    })
    expect(result.rejected).toEqual([{ record: disguised, reason: 'signature' }])
    expect(authorize).not.toHaveBeenCalled()
    expect(writes).toEqual([])
    expect(receiveClock).not.toHaveBeenCalled()
  })
})

describe('the five checks run in order', () => {
  test('an id past MAX_RECORD_ID_LENGTH is refused at the signature check', async () => {
    const identity = randomIdentity()
    // Hand-signed, since signing refuses the long id: only the claim check can reject it.
    const handSigned = async (id: string): Promise<SignedRecord> => {
      const claim = { ...claimFor(identity), id }
      const signed = await identity.signToken(
        { kind: 'kubun/record-op', claim: toB64U(fromUTF(canonicalStringify(claim))) },
        { embedLongForm: true },
      )
      const opJWT = stringifyToken(signed)
      const opHash = toB64U(blake3(fromUTF(`${opJWT.length}:${opJWT}`), { dkLen: 32 }))
      const { type, owner, hlc } = claim
      return { type, id, owner, hlc, payload: new Uint8Array([1]), opJWT, opHash }
    }
    const atBound = await handSigned('x'.repeat(MAX_RECORD_ID_LENGTH))
    const past = await handSigned('y'.repeat(MAX_RECORD_ID_LENGTH + 1))
    const authorize = vi.fn(async () => true)
    const { store, read } = memoryStore()
    const result = await applyWith([atBound, past], store, typesOf(valueType({ authorize })))
    expect(result.applied).toBe(1)
    expect(read('test.value', atBound.id)).toEqual(atBound)
    expect(result.rejected).toEqual([{ record: past, reason: 'signature' }])
    expect(authorize).toHaveBeenCalledTimes(1)
  })

  test('a forged token is rejected before the authorizer', async () => {
    const identity = randomIdentity()
    const genuine = await makeRecord(identity)
    const other = await makeRecord(identity, { payload: new Uint8Array([2]) })
    const [header, , signature] = genuine.opJWT.split('.')
    const [, payload] = other.opJWT.split('.')
    const forgedJWT = `${header}.${payload}.${signature}`
    expect(await verifyRecordOp(forgedJWT)).toBeNull()
    const forged = { ...other, opJWT: forgedJWT }
    const authorize = vi.fn(async () => true)
    const { store, writes } = memoryStore()
    const result = await applyWith([forged], store, typesOf(valueType({ authorize })))
    expect(result.rejected).toEqual([{ record: forged, reason: 'signature' }])
    expect(authorize).not.toHaveBeenCalled()
    expect(writes).toEqual([])
  })

  test('an unauthorized op is rejected before the policy and the digest', async () => {
    const owner = randomIdentity()
    const stranger = randomIdentity()
    const record = await makeRecord(stranger, {
      owner: normalizeDID(owner.id),
      meta: { version: [1] },
    })
    const version = vi.fn(VERSIONED.version)
    const { store, writes } = memoryStore()
    const result = await applyWith(
      [{ ...record, payload: new Uint8Array([9]) }],
      store,
      typesOf(valueType({ policy: { kind: 'monotonic', version } })),
    )
    expect(result.rejected[0]?.reason).toBe('unauthorized')
    expect(version).not.toHaveBeenCalled()
    expect(writes).toEqual([])
  })

  test('a losing op is a no-op before its payload is checked', async () => {
    const identity = randomIdentity()
    const newer = await makeRecord(identity, { offsetMS: 1000, payload: new Uint8Array([2]) })
    const older = await makeRecord(identity, { offsetMS: 0 })
    const { store, writes, read } = memoryStore([newer])
    const receiveClock = vi.fn()
    const result = await applyWith(
      [{ ...older, payload: new Uint8Array([9]) }],
      store,
      typesOf(valueType()),
      { receiveClock },
    )
    expect(result).toEqual({ applied: 0, parked: [], rejected: [], conflicts: [] })
    expect(writes).toEqual([])
    expect(read('test.value', 'one')).toEqual(newer)
    expect(receiveClock).not.toHaveBeenCalled()
  })

  test('a winning op with the wrong payload is rejected on its digest', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity)
    const tampered = { ...record, payload: new Uint8Array([9]) }
    const { store, writes } = memoryStore()
    const receiveClock = vi.fn()
    const result = await applyWith([tampered], store, typesOf(valueType()), { receiveClock })
    expect(result.rejected).toEqual([{ record: tampered, reason: 'digest' }])
    expect(writes).toEqual([])
    expect(receiveClock).not.toHaveBeenCalled()
  })

  test('a valid op is stored, and only then advances the clock', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity, { offsetMS: 30_000 })
    const { store, read } = memoryStore()
    const seen: Array<SignedRecord | null> = []
    const receiveClock = vi.fn((_stamp: HLCTimestamp) => {
      seen.push(read('test.value', 'one'))
    })
    const result = await applyWith([record], store, typesOf(valueType()), { receiveClock })
    expect(result).toEqual({ applied: 1, parked: [], rejected: [], conflicts: [] })
    expect(receiveClock).toHaveBeenCalledTimes(1)
    expect(receiveClock).toHaveBeenCalledWith(HLC.parse(record.hlc))
    expect(seen).toEqual([record])
  })

  test('an unknown type is rejected', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity, { type: 'test.other' })
    const { store, writes } = memoryStore()
    const result = await applyWith([record], store, typesOf(valueType()))
    expect(result.rejected).toEqual([{ record, reason: 'unknown-type' }])
    expect(writes).toEqual([])
  })
})

describe('first write', () => {
  test('a monotonic first write needs a valid version', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity, { meta: { version: 'one' } })
    const { store, writes } = memoryStore()
    const receiveClock = vi.fn()
    const result = await applyWith([record], store, typesOf(valueType({ policy: VERSIONED })), {
      receiveClock,
    })
    expect(result.rejected).toEqual([{ record, reason: 'version-invalid' }])
    expect(writes).toEqual([])
    expect(receiveClock).not.toHaveBeenCalled()
  })

  test('a monotonic first write with a valid version applies', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity, { meta: { version: [1, 0] } })
    const { store, read } = memoryStore()
    const result = await applyWith([record], store, typesOf(valueType({ policy: VERSIONED })))
    expect(result.applied).toBe(1)
    expect(read('test.value', 'one')).toEqual(record)
  })
})

describe('authorization', () => {
  test('the authorizer sees the record, the stored record, the chunk store and the receiver resolvers', async () => {
    const identity = randomIdentity()
    const stored = await makeRecord(identity)
    const incoming = await makeRecord(identity, { offsetMS: 1000 })
    const authorize = vi.fn(async (_op: VerifiedRecordOp, _ctx: RecordAuthorizeContext) => true)
    const resolveController = async () => null
    const verifyCapability = async () => false
    const { store } = memoryStore([stored])
    await applyWith([incoming], store, typesOf(valueType({ authorize })), {
      resolveController,
      verifyCapability,
    })
    const [op, ctx] = authorize.mock.calls[0] ?? []
    expect(op?.opHash).toBe(incoming.opHash)
    expect(op?.issuer).toBe(normalizeDID(identity.id))
    expect(ctx?.record).toBe(incoming)
    expect(ctx?.stored).toEqual(stored)
    // The chunk's transaction, not the store outside it: a read through it sees the
    // chunk's own write of the record.
    expect(ctx?.store).not.toBe(store)
    expect((await ctx?.store.get(stored))?.copies).toEqual([incoming])
    expect(await ctx?.resolveController(normalizeDID(identity.id))).toBeNull()
    expect(ctx?.verifyCapability).toBe(verifyCapability)
  })

  test('a device acting for its controller may write', async () => {
    const controller = normalizeDID(randomIdentity().id)
    const device = randomIdentity()
    const record = await makeRecord(device, { owner: controller })
    const { store, read } = memoryStore()
    const result = await applyWith([record], store, typesOf(valueType()), {
      resolveController: async (did) => (did === normalizeDID(device.id) ? controller : null),
    })
    expect(result.applied).toBe(1)
    expect(read('test.value', 'one')).toEqual(record)
  })

  test('a delegate needs a capability the owner granted', async () => {
    const owner = normalizeDID(randomIdentity().id)
    const delegate = randomIdentity()
    const record = await makeRecord(delegate, { owner, meta: { capability: ['chain'] } })
    const verifyCapability = vi.fn(async () => false)

    const refused = await applyWith([record], memoryStore().store, typesOf(valueType()), {
      verifyCapability,
    })
    expect(refused.rejected).toEqual([{ record, reason: 'unauthorized' }])
    expect(verifyCapability).toHaveBeenCalledWith(['chain'], owner, normalizeDID(delegate.id))

    const granted = await applyWith([record], memoryStore().store, typesOf(valueType()), {
      verifyCapability: async () => true,
    })
    expect(granted.applied).toBe(1)
  })

  test('a different owner writes an independent decision under the same id', async () => {
    const owner = randomIdentity()
    const taker = randomIdentity()
    const stored = await makeRecord(owner)
    const takeover = await makeRecord(taker, { offsetMS: 1000 })
    const { store, writes, read } = memoryStore([stored])
    const result = await applyWith(
      [takeover],
      store,
      typesOf(valueType({ authorize: async () => true })),
    )
    expect(result.applied).toBe(1)
    expect(writes).toEqual([takeover])
    expect(read('test.value', 'one', stored.owner)).toEqual(stored)
    expect(read('test.value', 'one', takeover.owner)).toEqual(takeover)
  })

  test('a peer:4 owner, signing with its long form embedded, keeps its record', async () => {
    const peer4 = await createIdentity({
      didMethod: 'peer:4',
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
    })
    const first = await makeRecord(peer4, { offsetMS: 0 })
    const second = await makeRecord(peer4, { offsetMS: 1000, payload: new Uint8Array([2]) })
    const { store, read } = memoryStore()
    const result = await applyWith([first, second], store, typesOf(valueType()))
    expect(result).toEqual({ applied: 2, parked: [], rejected: [], conflicts: [] })
    expect(read('test.value', 'one')).toEqual(second)
  })

  test('a stored row whose op no longer verifies yields to an older valid op', async () => {
    const owner = randomIdentity()
    const stored = await makeRecord(owner, { offsetMS: 1000 })
    const other = await makeRecord(owner, { offsetMS: 1000, payload: new Uint8Array([2]) })
    const [header, , signature] = stored.opJWT.split('.')
    const [, body] = other.opJWT.split('.')
    const corrupt = { ...stored, opJWT: `${header}.${body}.${signature}` }
    // An older write would lose against a row that verified.
    const incoming = await makeRecord(owner, { offsetMS: 0 })
    const authorize = vi.fn(ownerBinding)
    const { store, read } = memoryStore([corrupt])
    const result = await applyWith([incoming], store, typesOf(valueType({ authorize })))
    expect(result).toEqual({ applied: 1, parked: [], rejected: [], conflicts: [] })
    expect(authorize.mock.calls[0]?.[1].stored).toBeNull()
    expect(read('test.value', 'one')).toEqual(incoming)
  })

  test('a write claiming the stored owner from another issuer is unauthorized', async () => {
    const owner = randomIdentity()
    const taker = randomIdentity()
    const stored = await makeRecord(owner)
    const forged = await makeRecord(taker, { owner: normalizeDID(owner.id), offsetMS: 1000 })
    const { store, writes } = memoryStore([stored])
    const result = await applyWith([forged], store, typesOf(valueType()))
    expect(result.rejected).toEqual([{ record: forged, reason: 'unauthorized' }])
    expect(writes).toEqual([])
  })
})

describe('dependencies and parking', () => {
  const parentOf = (_record: SignedRecord, op: VerifiedRecordOp) =>
    typeof op.claim.meta.parent === 'string'
      ? [
          {
            type: op.claim.meta.parentType as string,
            owner: op.claim.owner,
            id: op.claim.meta.parent,
          },
        ]
      : []

  const chainTypes = () =>
    typesOf(
      valueType({ type: 'test.root' }),
      valueType({ type: 'test.child', dependsOn: ['test.root'], dependencies: parentOf }),
      valueType({ type: 'test.leaf', dependsOn: ['test.child'], dependencies: parentOf }),
    )

  async function chain(identity: TestIdentity) {
    const root = await makeRecord(identity, { type: 'test.root', id: 'r' })
    const child = await makeRecord(identity, {
      type: 'test.child',
      id: 'c',
      meta: { parentType: 'test.root', parent: 'r' },
    })
    const leaf = await makeRecord(identity, {
      type: 'test.leaf',
      id: 'l',
      meta: { parentType: 'test.child', parent: 'c' },
    })
    return { root, child, leaf }
  }

  test('a shuffled chunk applies in dependency order', async () => {
    const identity = randomIdentity()
    const { root, child, leaf } = await chain(identity)
    const { store, writes } = memoryStore()
    const result = await applyWith([leaf, root, child], store, chainTypes())
    expect(result).toEqual({ applied: 3, parked: [], rejected: [], conflicts: [] })
    expect(writes.map((record) => record.type)).toEqual(['test.root', 'test.child', 'test.leaf'])
  })

  test('type order applies a shuffled chain in one pass, with no record parked', async () => {
    const identity = randomIdentity()
    const { root, child, leaf } = await chain(identity)
    const dependencies = vi.fn(parentOf)
    const types = typesOf(
      valueType({ type: 'test.root' }),
      valueType({ type: 'test.child', dependsOn: ['test.root'], dependencies }),
      valueType({ type: 'test.leaf', dependsOn: ['test.child'], dependencies }),
    )
    const result = await applyWith([leaf, child, root], memoryStore().store, types)
    expect(result.applied).toBe(3)
    expect(dependencies.mock.calls.map(([record]) => record.id)).toEqual(['c', 'l'])
  })

  test('a dependency later in the chunk, within one type, resolves by retry', async () => {
    const identity = randomIdentity()
    const node = valueType({ type: 'test.node', dependencies: parentOf })
    const first = await makeRecord(identity, { type: 'test.node', id: 'a' })
    const second = await makeRecord(identity, {
      type: 'test.node',
      id: 'b',
      meta: { parentType: 'test.node', parent: 'a' },
    })
    const { store, writes } = memoryStore()
    const result = await applyWith([second, first], store, typesOf(node))
    expect(result).toEqual({ applied: 2, parked: [], rejected: [], conflicts: [] })
    expect(writes.map((record) => record.id)).toEqual(['a', 'b'])
  })

  test('a missing dependency parks without a side effect, and applies once supplied later in the session', async () => {
    const identity = randomIdentity()
    const { root, child } = await chain(identity)
    const { store, writes, read } = memoryStore()
    const authorize = vi.fn(ownerBinding)
    const types = typesOf(
      valueType({ type: 'test.root' }),
      valueType({
        type: 'test.child',
        dependsOn: ['test.root'],
        dependencies: parentOf,
        authorize,
      }),
    )
    const receiveClock = vi.fn()

    const first = await applyWith([child], store, types, { receiveClock })
    expect(first).toEqual({ applied: 0, parked: [child], rejected: [], conflicts: [] })
    expect(authorize).not.toHaveBeenCalled()
    expect(writes).toEqual([])
    expect(receiveClock).not.toHaveBeenCalled()

    const second = await applyWith([...first.parked, root], store, types, { receiveClock })
    expect(second).toEqual({ applied: 2, parked: [], rejected: [], conflicts: [] })
    expect(read('test.child', 'c')).toEqual(child)
    expect(receiveClock).toHaveBeenCalledTimes(2)
  })

  test('a parked record replays in a later session and is never dropped meanwhile', async () => {
    const identity = randomIdentity()
    const { root, child, leaf } = await chain(identity)
    const { store, read } = memoryStore()
    const types = chainTypes()

    const session1 = await applyWith([leaf], store, types)
    expect(session1.parked).toEqual([leaf])

    // Still missing in the next session: parked again, not rejected.
    const session2 = await applyWith(session1.parked, store, types, { nowMS: NOW + DAY_MS })
    expect(session2).toEqual({ applied: 0, parked: [leaf], rejected: [], conflicts: [] })

    // A later session supplies the dependencies from another peer, then replays the queue.
    const session3 = await applyWith([root, child], store, types, { nowMS: NOW + 2 * DAY_MS })
    expect(session3.applied).toBe(2)
    const replay = await applyWith(session2.parked, store, types, { nowMS: NOW + 2 * DAY_MS })
    expect(replay).toEqual({ applied: 1, parked: [], rejected: [], conflicts: [] })
    expect(read('test.leaf', 'l')).toEqual(leaf)
  })

  test('dependencies read the signed claim', async () => {
    const identity = randomIdentity()
    const { child } = await chain(identity)
    const dependencies = vi.fn(parentOf)
    await applyWith(
      [child],
      memoryStore().store,
      typesOf(
        valueType({ type: 'test.root' }),
        valueType({ type: 'test.child', dependsOn: ['test.root'], dependencies }),
      ),
    )
    const [record, op] = dependencies.mock.calls[0] ?? []
    expect(record).toEqual(child)
    expect(op?.claim.meta).toEqual({ parentType: 'test.root', parent: 'r' })
  })

  describe('a dependency present at too old a version', () => {
    const keyType = () => valueType({ type: 'test.key', policy: VERSIONED })
    const wrappingType = () =>
      valueType({
        type: 'test.wrapping',
        dependsOn: ['test.key'],
        dependencies: (_record, op) => [
          {
            type: 'test.key',
            owner: op.claim.owner,
            id: op.claim.meta.keyID as string,
            satisfiedBy: (stored) =>
              ((stored.claim.meta.version as Array<number>)[0] as number) >=
              (op.claim.meta.keyVersion as number),
          },
        ],
      })

    async function keyAndWrapping(identity: TestIdentity) {
      const keyV2 = await makeRecord(identity, {
        type: 'test.key',
        id: 'k',
        meta: { version: [2] },
      })
      const keyV3 = await makeRecord(identity, {
        type: 'test.key',
        id: 'k',
        offsetMS: 1000,
        payload: new Uint8Array([3]),
        meta: { version: [3] },
      })
      const wrapping = await makeRecord(identity, {
        type: 'test.wrapping',
        id: 'w',
        meta: { keyID: 'k', keyVersion: 3 },
      })
      return { keyV2, keyV3, wrapping }
    }

    test('parks, and applies once a later chunk stores the version it needs', async () => {
      const identity = randomIdentity()
      const { keyV2, keyV3, wrapping } = await keyAndWrapping(identity)
      const { store, read } = memoryStore([keyV2])
      const authorize = vi.fn(ownerBinding)
      const types = typesOf(keyType(), { ...wrappingType(), authorize })

      const first = await applyWith([wrapping], store, types)
      expect(first).toEqual({ applied: 0, parked: [wrapping], rejected: [], conflicts: [] })
      expect(authorize).not.toHaveBeenCalled()
      expect(read('test.wrapping', 'w')).toBeNull()

      const second = await applyWith([...first.parked, keyV3], store, types)
      expect(second).toEqual({ applied: 2, parked: [], rejected: [], conflicts: [] })
      expect(read('test.wrapping', 'w')).toEqual(wrapping)
    })

    test('applies within the chunk that also carries the version it needs', async () => {
      const identity = randomIdentity()
      const { keyV2, keyV3, wrapping } = await keyAndWrapping(identity)
      const { store, read } = memoryStore([keyV2])
      const result = await applyWith([wrapping, keyV3], store, typesOf(keyType(), wrappingType()))
      expect(result).toEqual({ applied: 2, parked: [], rejected: [], conflicts: [] })
      expect(read('test.wrapping', 'w')).toEqual(wrapping)
    })
  })

  test('a dependency cycle between types is refused', async () => {
    const types = typesOf(
      valueType({ type: 'test.a', dependsOn: ['test.b'] }),
      valueType({ type: 'test.b', dependsOn: ['test.a'] }),
    )
    await expect(applyWith([], memoryStore().store, types)).rejects.toThrow(RecordTypeGraphError)
  })
})

describe('duplicates, replays and tombstones', () => {
  test('a duplicate in the chunk and a later replay are no-ops', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity)
    const { store, writes } = memoryStore()
    const afterApply = vi.fn(async () => {})
    const types = typesOf(valueType({ afterApply }))
    const receiveClock = vi.fn()

    const first = await applyWith([record, record], store, types, { receiveClock })
    expect(first).toEqual({ applied: 1, parked: [], rejected: [], conflicts: [] })
    const replay = await applyWith([record], store, types, { receiveClock })
    expect(replay).toEqual({ applied: 0, parked: [], rejected: [], conflicts: [] })
    expect(writes).toEqual([record])
    expect(afterApply).toHaveBeenCalledTimes(1)
    expect(receiveClock).toHaveBeenCalledTimes(1)
  })

  test('a replay of the stored op is a no-op even once its writer is no longer authorized', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity)
    const { store } = memoryStore([record])
    const authorize = vi.fn(async () => false)
    const result = await applyWith([record], store, typesOf(valueType({ authorize })))
    expect(result).toEqual({ applied: 0, parked: [], rejected: [], conflicts: [] })
    expect(authorize).not.toHaveBeenCalled()
  })

  test('a stored copy remains a no-op when its precheck now fails', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity)
    const { store, writes } = memoryStore([record])
    const precheck = vi.fn(async () => false)
    const authorize = vi.fn(async () => true)
    const result = await applyWith([record], store, typesOf(valueType({ precheck, authorize })))
    expect(result).toEqual({ applied: 0, parked: [], rejected: [], conflicts: [] })
    expect(writes).toEqual([])
    expect(authorize).not.toHaveBeenCalled()
  })

  test('a tombstone replaces an older write and holds off an older re-add', async () => {
    const identity = randomIdentity()
    const write = await makeRecord(identity, { offsetMS: 0 })
    const tombstone = await makeRecord(identity, { offsetMS: 1000, payload: null })
    const staleReAdd = await makeRecord(identity, { offsetMS: 500, payload: new Uint8Array([3]) })
    const reAdd = await makeRecord(identity, { offsetMS: 2000, payload: new Uint8Array([4]) })
    const { store, read } = memoryStore([write])
    const types = typesOf(valueType())

    expect((await applyWith([tombstone], store, types)).applied).toBe(1)
    expect(read('test.value', 'one')).toEqual(tombstone)
    expect(await applyWith([staleReAdd], store, types)).toEqual({
      applied: 0,
      parked: [],
      rejected: [],
      conflicts: [],
    })
    expect(read('test.value', 'one')).toEqual(tombstone)
    expect((await applyWith([reAdd], store, types)).applied).toBe(1)
    expect(read('test.value', 'one')).toEqual(reAdd)
  })

  test('a tombstone carrying a payload is rejected on its digest', async () => {
    const identity = randomIdentity()
    const tombstone = await makeRecord(identity, { payload: null })
    const stuffed = { ...tombstone, payload: new Uint8Array([1]) }
    const { store, writes } = memoryStore()
    const result = await applyWith([stuffed], store, typesOf(valueType()))
    expect(result.rejected).toEqual([{ record: stuffed, reason: 'digest' }])
    expect(writes).toEqual([])
  })
})

describe('conflicts', () => {
  async function equalVersionPair() {
    const identity = randomIdentity()
    const a = await makeRecord(identity, { meta: { version: [3] }, payload: new Uint8Array([1]) })
    const b = await makeRecord(identity, { meta: { version: [3] }, payload: new Uint8Array([2]) })
    return (await recordDecisionDigest(a)) > (await recordDecisionDigest(b))
      ? { high: a, low: b }
      : { high: b, low: a }
  }

  test.each([
    ['resolve', undefined],
    ['fork', () => 'fork' as const],
  ])(
    'an equal-version pair converges on the greater content digest and is reported (%s)',
    async (mode, onEqual) => {
      const { high, low } = await equalVersionPair()
      const types = typesOf(valueType({ policy: VERSIONED, onEqual }))
      for (const [first, second] of [
        [high, low],
        [low, high],
      ] as const) {
        const { store, read } = memoryStore([first])
        const result = await applyWith([second], store, types)
        expect(read('test.value', 'one')).toEqual(high)
        expect(result.conflicts).toEqual([
          {
            record: second,
            storedOpHash: first.opHash,
            incomingOpHash: second.opHash,
            forked: mode === 'fork',
          },
        ])
      }
    },
  )

  test('re-stamping identical content under an immutable id is reported', async () => {
    const identity = randomIdentity()
    const a = await makeRecord(identity, { offsetMS: 0 })
    const b = await makeRecord(identity, { offsetMS: 1000 })
    const high = (await recordDecisionDigest(a)) > (await recordDecisionDigest(b)) ? a : b
    const types = typesOf(valueType({ policy: { kind: 'immutable' } }))
    for (const [first, second] of [
      [a, b],
      [b, a],
    ] as const) {
      const { store, read } = memoryStore()
      const result = await applyWith([first, second], store, types)
      expect(read('test.value', 'one')).toEqual(high)
      expect(result.conflicts).toHaveLength(1)
      expect(result.conflicts[0]?.forked).toBe(false)
    }
  })
})

describe('transactions', () => {
  test('afterApply runs inside the transaction, after the record is stored', async () => {
    const identity = randomIdentity()
    const record = await makeRecord(identity)
    const { store, read } = memoryStore()
    const observed: Array<[SignedRecord | null, SignedRecord | null]> = []
    const afterApply = vi.fn(async (applied: SignedRecord, tx: RecordStoreAdapter) => {
      observed.push([(await tx.get(applied))?.copies[0] ?? null, read(applied.type, applied.id)])
    })
    await applyWith([record], store, typesOf(valueType({ afterApply })))
    expect(afterApply).toHaveBeenCalledWith(record, expect.anything())
    expect(observed).toEqual([[record, null]])
  })

  test('a failure rolls the whole chunk back and advances no clock', async () => {
    const identity = randomIdentity()
    const one = await makeRecord(identity, { id: 'one' })
    const two = await makeRecord(identity, { id: 'two' })
    const { store, read } = memoryStore()
    const receiveClock = vi.fn()
    const types = typesOf(
      valueType({
        afterApply: async (record) => {
          if (record.id === 'two') {
            throw new Error('after-apply failed')
          }
        },
      }),
    )
    await expect(applyWith([one, two], store, types, { receiveClock })).rejects.toThrow(
      'after-apply failed',
    )
    expect(read('test.value', 'one')).toBeNull()
    expect(receiveClock).not.toHaveBeenCalled()
  })

  test('passes all chunk keys in one call before reading or deciding', async () => {
    const identity = randomIdentity()
    const a = await makeRecord(identity, { id: 'A', meta: { keyID: 'A' } })
    const b = await makeRecord(identity, { id: 'B', meta: { keyID: 'B' } })
    const memory = memoryStore()
    const events: Array<string> = []
    const store: RecordStoreAdapter = {
      ...memory.store,
      async transaction(fn) {
        return await memory.store.transaction(
          async (tx) =>
            await fn({
              ...tx,
              lock: async (keys) => {
                events.push(`lock:${keys.map(({ key }) => key).join(',')}`)
              },
              get: async (key) => {
                events.push(`read:${key.id}`)
                return await tx.get(key)
              },
            }),
        )
      },
    }
    const definition = valueType({
      lockKeys: (incoming) => [{ type: incoming.type, key: incoming.id }],
    })
    const result = await applyWith([b, a], store, typesOf(definition))
    expect(result.applied).toBe(2)
    expect(events[0]).toBe('lock:A,B')
    expect(events.indexOf('read:B')).toBeGreaterThan(0)
  })

  test('resolves a device controller before acquiring record locks', async () => {
    const owner = normalizeDID(randomIdentity().id)
    const device = randomIdentity()
    const record = await makeRecord(device, { owner })
    const memory = memoryStore()
    const events: Array<string> = []
    const store: RecordStoreAdapter = {
      ...memory.store,
      transaction: async (fn) =>
        await memory.store.transaction(
          async (tx) =>
            await fn({
              ...tx,
              lock: async () => {
                events.push('lock')
              },
            }),
        ),
    }
    const result = await applyWith(
      [record],
      store,
      typesOf(valueType({ lockKeys: () => [{ type: 'test.value', key: 'one' }] })),
      {
        resolveController: async () => {
          events.push('controller')
          return owner
        },
      },
    )
    expect(result.applied).toBe(1)
    expect(events.indexOf('controller')).toBeLessThan(events.indexOf('lock'))
  })

  test('retries a chunk when a stored move source changes before locking', async () => {
    const identity = randomIdentity()
    const old = await makeRecord(identity, { id: 'entry', offsetMS: -3, meta: { keyID: 'A' } })
    const moved = await makeRecord(identity, { id: 'entry', offsetMS: -2, meta: { keyID: 'B' } })
    const incoming = await makeRecord(identity, { id: 'entry', offsetMS: -1, meta: { keyID: 'C' } })
    const memory = memoryStore([old])
    const events: Array<string> = []
    const transactions: Array<RecordStoreAdapter> = []
    let first = true
    const store: RecordStoreAdapter = {
      ...memory.store,
      async transaction(fn) {
        if (first) {
          first = false
          await memory.store.putCopy(moved)
        }
        return await memory.store.transaction(async (tx) => {
          transactions.push(tx)
          return await fn({
            ...tx,
            lock: async (keys) => {
              events.push(...keys.map(({ key }) => key))
            },
          })
        })
      },
    }
    const definition = valueType({
      lockKeys: (record, stored) =>
        [record.opHash, stored?.copies[0]?.opHash]
          .filter((key): key is string => key != null)
          .map((key) => ({ type: record.type, key })),
    })
    const result = await applyWith([incoming], store, typesOf(definition))
    expect(result.applied).toBe(1)
    expect(events).toContain(moved.opHash)
    expect(transactions).toHaveLength(2)
    expect(transactions[0]).not.toBe(transactions[1])
    expect(memory.read('test.value', 'entry')?.opHash).toBe(incoming.opHash)
  })

  test('an ambient transaction aborts on a changed lock set without retrying inline', async () => {
    const identity = randomIdentity()
    const old = await makeRecord(identity, { id: 'entry', offsetMS: -3, meta: { keyID: 'A' } })
    const moved = await makeRecord(identity, { id: 'entry', offsetMS: -2, meta: { keyID: 'B' } })
    const incoming = await makeRecord(identity, { id: 'entry', offsetMS: -1, meta: { keyID: 'C' } })
    const memory = memoryStore([old])
    let locks = 0
    const definition = valueType({
      lockKeys: (record, stored) =>
        [record.opHash, stored?.copies[0]?.opHash]
          .filter((key): key is string => key != null)
          .map((key) => ({ type: record.type, key })),
    })
    await expect(
      memory.store.transaction(async (tx) => {
        const ambient: RecordStoreAdapter = {
          ...tx,
          isTransaction: true,
          async transaction(fn) {
            return await fn(ambient)
          },
          async get(key) {
            return locks === 0 ? decisionOf(old) : await tx.get(key)
          },
          async lock() {
            locks += 1
            await tx.putCopy(moved)
          },
        }
        return await applyWith([incoming], ambient, typesOf(definition))
      }),
    ).rejects.toBeInstanceOf(RecordSourceChangedError)
    expect(locks).toBe(1)
    expect(memory.read('test.value', 'entry')?.opHash).toBe(old.opHash)
  })

  test('an owned transaction surfaces a mismatch after five fresh attempts', async () => {
    const identity = randomIdentity()
    const incoming = await makeRecord(identity, { id: 'entry' })
    const memory = memoryStore()
    let attempts = 0
    let lockReads = 0
    const store: RecordStoreAdapter = {
      ...memory.store,
      async transaction(fn) {
        attempts += 1
        return await memory.store.transaction(
          async (tx) => await fn({ ...tx, lock: async () => {} }),
        )
      },
    }
    const definition = valueType({
      lockKeys: () => [{ type: 'test.value', key: String(++lockReads) }],
    })
    await expect(applyWith([incoming], store, typesOf(definition))).rejects.toBeInstanceOf(
      RecordSourceChangedError,
    )
    expect(attempts).toBe(5)
    expect(memory.read('test.value', 'entry')).toBeNull()
  })
})

describe('afterAuthorize hook', () => {
  test('retains an authorized losing op but never sees unauthorized or digest-mismatched ops', async () => {
    const identity = randomIdentity()
    const stranger = randomIdentity()
    const newer = await makeRecord(identity, { offsetMS: 1000, payload: new Uint8Array([2]) })
    const older = await makeRecord(identity, { payload: new Uint8Array([1]) })
    const unauthorized = await makeRecord(stranger, {
      owner: normalizeDID(identity.id),
      offsetMS: 2000,
    })
    const digestMismatch = {
      ...(await makeRecord(identity, { offsetMS: 3000, payload: new Uint8Array([3]) })),
      payload: new Uint8Array([4]),
    }
    const { store, read } = memoryStore([newer])
    const retained: Array<string> = []
    const types = typesOf(
      valueType({
        afterAuthorize: async (record) => {
          retained.push(record.opHash)
        },
      }),
    )

    await applyWith([older], store, types)
    expect(retained).toEqual([older.opHash])
    expect(read('test.value', 'one')).toEqual(newer)

    await applyWith([unauthorized, digestMismatch], store, types)
    expect(retained).toEqual([older.opHash])
    expect(read('test.value', 'one')).toEqual(newer)
  })
})
