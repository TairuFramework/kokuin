import { Buffer } from 'node:buffer'
import { readFileSync } from 'node:fs'
import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import {
  CODECS,
  createSigningIdentity,
  getDID,
  type MethodRegistry,
  type SigningIdentity,
} from '@kokuin/token'
import { b64uFromJSON, fromUTF, toB64U, toUTF } from '@sozai/codec'
import { HLC } from '@sozai/hlc'
import { beforeEach, expect, test } from 'vitest'

import {
  applyRecordChunk,
  type RecordTypeDefinition,
  type VisibilityContext,
} from '../src/apply.js'
import {
  clearRecordOpMemo,
  createRecordVerifier,
  signRecordOp,
  verifyRecordOp,
  verifySignedRecord,
} from '../src/op.js'
import { fingerprintRange, rangeLeaf, splitRange, summarizeRange } from '../src/range.js'
import { advanceRecordPull, beginRecordPull } from '../src/reconcile.js'
import {
  canonicalRecordClaim,
  recordClaimDigest,
  recordPayloadDigest,
  recordPayloadMatches,
  type SignedRecord,
} from '../src/record.js'
import type { RecordStoreAdapter } from '../src/store.js'
import { filterVisibleRecords, verifyHolderProof, visibilityRules } from '../src/visibility.js'
import { CONTENT, claimFixture } from './crypto-fixture.js'
import { decisionOf } from './decision-fixture.js'

const identity = createSigningIdentity(new Uint8Array(32).fill(7))

function provider(overrides: Partial<CryptoProvider> = {}) {
  const hashes: Array<Uint8Array> = []
  let verifications = 0
  const crypto: CryptoProvider = {
    ...nobleCrypto,
    async blake3(input, length) {
      hashes.push(new Uint8Array(input))
      return nobleCrypto.blake3(input, length)
    },
    async verify(...args) {
      verifications++
      return nobleCrypto.verify(...args)
    },
    ...overrides,
  }
  return { crypto, hashes, count: () => verifications }
}
function gate() {
  let release = () => {}
  const waiting = new Promise<void>((resolve) => {
    release = resolve
  })
  return { waiting, release }
}
async function record(): Promise<SignedRecord> {
  return {
    ...claimFixture,
    payload: new Uint8Array([1, 2, 3]),
    ...(await signRecordOp(identity, claimFixture, 'test/op')),
  }
}
beforeEach(clearRecordOpMemo)

test('canonical digest, op framing and empty fingerprint retain literal golden bytes', async () => {
  const p = provider()
  expect(await recordClaimDigest(claimFixture, p)).toBe(CONTENT)
  expect(
    await recordClaimDigest({ ...claimFixture, meta: { ...claimFixture.meta, version: 2 } }, p),
  ).toBe('IJKJuqLYXQfjzOk1GBeNniNSOcZqh4MWjTEWlM_43ZM')
  expect(await recordPayloadDigest(new Uint8Array(), p)).toBe(
    'rxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI',
  )
  expect(await recordPayloadDigest(null, p)).toBeNull()
  expect(await fingerprintRange([], p)).toBe('JFCXv71wSdsvuagATLBw8Q')
  expect((await signRecordOp(identity, claimFixture, 'test/op', p)).opHash).toBe(
    'FmNIB2Tr9nMt9t8Z6BwPwPGiExcwpqOoyTw1HVUSol8',
  )
  expect(p.hashes).toHaveLength(5)
})

test('cold verification carries its digest and warm verification skips signature and claim hashing', async () => {
  const row = await record()
  const p = provider()
  const op = await verifySignedRecord(row, 'test/op', undefined, p)
  expect(op?.contentDigest).toBe(CONTENT)
  expect(p.count()).toBe(1)
  expect(p.hashes).toHaveLength(2)
  if (op) {
    expect(() => {
      op.claim.meta.version = 'mutated'
    }).toThrow(TypeError)
    expect(() => {
      op.contentDigest = 'mutated'
    }).toThrow(TypeError)
  }
  expect((await verifySignedRecord(row, 'test/op', undefined, p))?.contentDigest).toBe(CONTENT)
  expect(p.count()).toBe(1)
  expect(p.hashes).toHaveLength(3)
})

test('permissive providers cannot authorise rejecting providers, concurrently or on retry', async () => {
  const row = await record()
  const accepting = provider()
  const rejecting = provider({
    async verify() {
      calls++
      return false
    },
  })
  let calls = 0
  await verifySignedRecord(row, 'test/op', undefined, accepting)
  expect(
    await Promise.all([1, 2].map(() => verifySignedRecord(row, 'test/op', undefined, rejecting))),
  ).toEqual([null, null])
  expect(calls).toBeGreaterThan(0)
  const previous = calls
  expect(await verifySignedRecord(row, 'test/op', undefined, rejecting)).toBeNull()
  expect(calls).toBeGreaterThan(previous)
})

test('signature and hash operational rejections escape refusal and remain retryable', async () => {
  const row = await record()
  const sentinel = new Error('provider unavailable')
  let calls = 0
  const p = provider({
    async verify() {
      calls++
      throw sentinel
    },
  })
  const verify = createRecordVerifier('test/op', undefined, p)
  for (let attempt = 0; attempt < 2; attempt++) await expect(verify(row)).rejects.toBe(sentinel)
  expect(calls).toBe(2)
  await expect(
    verifyRecordOp(
      row.opJWT,
      'test/op',
      undefined,
      provider({
        async blake3() {
          throw sentinel
        },
      }),
    ),
  ).rejects.toBe(sentinel)
})

test('claim hashing and Buffer payload checks own inputs before provider suspension', async () => {
  const g = gate()
  const captured: Array<Uint8Array> = []
  const p = provider({
    async blake3(input, length) {
      captured.push(input)
      await g.waiting
      return nobleCrypto.blake3(input, length)
    },
  })
  const claim = structuredClone(claimFixture)
  const pendingClaim = recordClaimDigest(claim, p)
  const bytes = Buffer.from([0, 1, 2, 3, 0])
  const row = { ...(await record()), payload: bytes.subarray(1, 4) }
  const pendingPayload = recordPayloadMatches(row, claim, p)
  claim.meta.version = 'changed'
  claim.payloadDigest = 'changed'
  bytes.fill(9)
  expect(toUTF(captured[0] ?? fromUTF('missing'))).toContain('2025-01-01')
  g.release()
  expect(await pendingClaim).toBe(CONTENT)
  expect(await pendingPayload).toBe(true)
})

test('record bindings and verifier options are captured before hashing suspends', async () => {
  const row = await record()
  const original = structuredClone(row)
  const g = gate()
  let entered = () => {}
  const started = new Promise<void>((resolve) => {
    entered = resolve
  })
  const p = provider({
    async blake3(input, length) {
      entered()
      await g.waiting
      return nobleCrypto.blake3(input, length)
    },
  })
  const options = { crypto: p.crypto }
  const verify = createRecordVerifier('test/op', undefined, options)
  const pending = verify(row)
  await started
  row.id = 'changed'
  row.opHash = 'changed'
  options.crypto = provider({
    async verify() {
      return false
    },
  }).crypto
  g.release()
  const op = await pending
  expect(op?.claim.id).toBe(original.id)
  expect(op?.contentDigest).toBe(CONTENT)
  expect((await verify(original))?.contentDigest).toBe(CONTENT)
})

test.each([false, true])(
  'a rejected payload hash rolls back writes and clocks with ambient transaction %s',
  async (ambient) => {
    const row = await record()
    // A canonical HLC keeps the failure at the payload boundary.
    const claim = {
      ...claimFixture,
      hlc: HLC.serialize({ wallTime: Date.parse('2026-01-01'), counter: 0, nodeID: 'node' }),
    }
    const first = { ...row, ...claim, ...(await signRecordOp(identity, claim, 'test/op')) }
    const secondClaim = { ...claim, id: 'second' }
    const second = {
      ...first,
      ...secondClaim,
      ...(await signRecordOp(identity, secondClaim, 'test/op')),
    }
    const sentinel = new Error('payload unavailable')
    let payloadCalls = 0
    const p = provider({
      async blake3(input, length) {
        if (input.length === 3 && ++payloadCalls === 2) throw sentinel
        return nobleCrypto.blake3(input, length)
      },
    })
    let rows = new Map<string, SignedRecord>()
    let writes = 0
    let clocks = 0
    const over = (view: Map<string, SignedRecord>): RecordStoreAdapter => {
      const adapter: RecordStoreAdapter = {
        isTransaction: true,
        async get(key) {
          const held = view.get(key.id)
          return held === undefined ? null : decisionOf(held)
        },
        async list() {
          return [...view.values()].map(decisionOf)
        },
        async pruneCopy() {},
        async putCopy(row) {
          writes++
          view.set(row.id, row)
        },
        async transaction(fn) {
          return fn(adapter)
        },
      }
      return adapter
    }
    const store: RecordStoreAdapter = {
      ...over(rows),
      isTransaction: false,
      async transaction(fn) {
        const draft = new Map(rows)
        const result = await fn(over(draft))
        rows = draft
        return result
      },
    }
    const apply = (bound: RecordStoreAdapter) =>
      applyRecordChunk({
        ...p,
        opKind: 'test/op',
        records: [first, second],
        store: bound,
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
        receiveClock: () => {
          clocks++
        },
        resolveController: async () => null,
        verifyCapability: async () => true,
      })
    await expect(ambient ? store.transaction(apply) : apply(store)).rejects.toBe(sentinel)
    expect(writes).toBe(1)
    expect(rows.size).toBe(0)
    expect(clocks).toBe(0)
  },
)

test('holder-proof refusal preserves provider operational failures', async () => {
  const row = await record()
  const sentinel = new Error('proof provider unavailable')
  const p = provider({
    async verify() {
      throw sentinel
    },
  })
  const store: RecordStoreAdapter = {
    async get() {
      return null
    },
    async list() {
      return []
    },
    async putCopy() {},
    async pruneCopy() {},
    async transaction(fn) {
      return fn(store)
    },
  }
  await expect(
    verifyHolderProof(row, {
      ...p,
      opKind: 'test/op',
      requester: { peerDID: identity.id, controllerDID: null },
      proofs: [],
      store,
      authorizeProof: async () => true,
      currentKeyVersion: async () => 1,
      isGroupMember: async () => false,
      holderTypes: new Map([
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
    }),
  ).rejects.toBe(sentinel)
})

test('signing snapshots nested claims and serialises hashing with hardware requests', async () => {
  const g = gate()
  let hashing = false
  let calls = 0
  const p = provider({
    async blake3(input, length) {
      hashing = true
      await g.waiting
      hashing = false
      return nobleCrypto.blake3(input, length)
    },
  })
  const signer: SigningIdentity = {
    ...identity,
    async signToken(payload, options) {
      expect(hashing).toBe(false)
      calls++
      return identity.signToken(payload, options)
    },
  }
  const claim = structuredClone(claimFixture)
  const first = signRecordOp(signer, claim, 'test/op', p)
  const second = signRecordOp(signer, claim, 'test/op', p)
  claim.meta.version = 'changed'
  for (let turn = 0; turn < 20 && !hashing; turn++) await Promise.resolve()
  expect(calls).toBe(1)
  g.release()
  const signed = await Promise.all([first, second])
  expect(signed[0]).toEqual(signed[1])
  const signedFirst = signed[0]
  if (signedFirst === undefined) throw new Error('Missing signed record')
  expect((await verifyRecordOp(signedFirst.opJWT, 'test/op'))?.contentDigest).toBe(CONTENT)
})

test('ranges preserve golden leaf bytes, signer deduplication, lane sums and requester routing', async () => {
  const row = await record()
  const p = provider()
  const leaf = await rangeLeaf(
    {
      key: { type: row.type, owner: row.owner, id: row.id },
      decisionHLC: row.hlc,
      contentDigest: CONTENT,
      copies: [row, row],
    },
    { kind: 'immutable' },
    p,
  )
  expect(leaf?.opHash).toBe('oiXwlZNyqiOW9l7PQpbdQP1PNgLJf8K4Uh9mur26xXw')
  expect(leaf?.signers).toEqual([identity.id])
  if (leaf === null) throw new Error('missing leaf')
  expect(await fingerprintRange([leaf], p)).toBe('DldB859DFDMw4zhk5hCQHA')
  const leaves = [leaf, { ...leaf, id: 'a' }, { ...leaf, id: 'b' }]
  expect(await fingerprintRange(leaves, p)).toBe('9RgshWkgnni8D6A8RkWJ_Q')
  expect(await fingerprintRange([...leaves].reverse(), p)).toBe('9RgshWkgnni8D6A8RkWJ_Q')
  const bounds = { type: row.type, lower: null, upper: null }
  const summary = await summarizeRange(leaves, bounds, p)
  expect(summary.fingerprint).toBe('9RgshWkgnni8D6A8RkWJ_Q')
  const children = await splitRange(leaves, bounds, 1, p)
  expect(children).toHaveLength(3)
  const advanced = await advanceRecordPull(beginRecordPull([row.type]), leaves, summary, p)
  expect(advanced.steps).toEqual([{ answer: 'matches', bounds }])
  expect(advanced.state.complete).toBe(true)
  expect(p.hashes).toHaveLength(9)
  expect(p.hashes.map((input) => input.length).slice(1)).toEqual(Array(8).fill(36))
})

test('split summaries retain captured provider and bounds across suspension', async () => {
  const row = await record()
  const leaf = await rangeLeaf(
    { key: row, decisionHLC: row.hlc, contentDigest: CONTENT, copies: [row] },
    { kind: 'immutable' },
  )
  if (leaf === null) throw new Error('missing leaf')
  const g = gate()
  let calls = 0
  const p = provider({
    async blake3(input, length) {
      calls++
      await g.waiting
      return nobleCrypto.blake3(input, length)
    },
  })
  const options = { crypto: p.crypto }
  const bounds = { type: row.type, lower: null, upper: null }
  const pending = splitRange([leaf, { ...leaf, id: 'a' }], bounds, 1, options)
  options.crypto = provider({
    async blake3() {
      throw new Error('replacement provider')
    },
  }).crypto
  bounds.type = 'changed'
  g.release()
  expect(await pending).toHaveLength(2)
  expect(calls).toBe(2)
})

test('suspended signature verification cannot persist substituted record bytes or bindings', async () => {
  const g = gate()
  let entered = () => {}
  const started = new Promise<void>((resolve) => {
    entered = resolve
  })
  const p = provider({
    async verify(...args) {
      entered()
      await g.waiting
      return nobleCrypto.verify(...args)
    },
  })
  const claim = {
    ...claimFixture,
    hlc: HLC.serialize({ wallTime: Date.parse('2026-01-01'), counter: 0, nodeID: 'node' }),
  }
  const bytes = Buffer.from([0, 1, 2, 3, 0])
  const row = {
    ...claim,
    payload: bytes.subarray(1, 4),
    ...(await signRecordOp(identity, claim, 'test/op')),
  }
  const original = { ...row, payload: new Uint8Array([1, 2, 3]) }
  let persisted: SignedRecord | undefined
  const store: RecordStoreAdapter = {
    async get() {
      return null
    },
    async list() {
      return []
    },
    async putCopy(value) {
      persisted = value
    },
    async pruneCopy() {},
    async transaction(fn) {
      return fn(store)
    },
  }
  const pending = applyRecordChunk({
    ...p,
    opKind: 'test/op',
    records: [row],
    store,
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
  await started
  row.id = 'substituted'
  bytes.fill(9)
  g.release()
  expect((await pending).applied).toBe(1)
  expect(persisted).toEqual(original)
  expect((await verifySignedRecord(original, 'test/op', undefined, p))?.claim.id).toBe('雪')
})

test('failed carried-digest construction does not populate the operation memo', async () => {
  const row = await record()
  const sentinel = new Error('content digest unavailable')
  let hashes = 0
  let failing = true
  const p = provider({
    async blake3(input, length) {
      hashes++
      if (toUTF(input).startsWith('{') && failing) throw sentinel
      return nobleCrypto.blake3(input, length)
    },
  })
  await expect(verifySignedRecord(row, 'test/op', undefined, p)).rejects.toBe(sentinel)
  failing = false
  expect((await verifySignedRecord(row, 'test/op', undefined, p))?.contentDigest).toBe(CONTENT)
  expect(hashes).toBe(4)
})

test('method registry policy cannot change during suspended operation hashing', async () => {
  const row = await record()
  const g = gate()
  const p = provider({
    async blake3(input, length) {
      await g.waiting
      return nobleCrypto.blake3(input, length)
    },
  })
  const methods: Array<MethodRegistry[number]> = []
  const pending = verifyRecordOp(row.opJWT, 'test/op', methods, p)
  methods.push({
    method: 'key',
    async resolve() {
      throw new Error('replacement resolver')
    },
  })
  g.release()
  expect((await pending)?.contentDigest).toBe(CONTENT)
})

test('strict verification refuses a correctly framed small-order corpus forgery', async () => {
  const corpus = JSON.parse(
    readFileSync(new URL('../../crypto-conformance/vectors/corpus.json', import.meta.url), 'utf8'),
  ) as { verify: Array<{ name: string; publicKey: string; signature: string }> }
  const vector = corpus.verify.find(
    (entry) => entry.name === 'Ed25519 identity public key and R with S = 0',
  )
  if (vector === undefined) throw new Error('Missing identity corpus fixture')
  const iss = getDID(CODECS.EdDSA, new Uint8Array(Buffer.from(vector.publicKey, 'hex')))
  const data = `${b64uFromJSON({ typ: 'JWT', alg: 'EdDSA' })}.${b64uFromJSON({ iss, kind: 'test/op', claim: toB64U(canonicalRecordClaim(claimFixture)) })}`
  const token = `${data}.${toB64U(new Uint8Array(Buffer.from(vector.signature, 'hex')))}`
  expect(await verifyRecordOp(token, 'test/op')).toBeNull()
  expect(
    (
      await verifyRecordOp(
        token,
        'test/op',
        undefined,
        provider({
          async verify() {
            return true
          },
        }),
      )
    )?.contentDigest,
  ).toBe(CONTENT)
})

test('tombstone content keeps its golden digest without hashing an absent payload', async () => {
  const p = provider()
  const claim = { ...claimFixture, payloadDigest: null, deleted: true, meta: {} }
  expect(await recordClaimDigest(claim, p)).toBe('pE0m65URmEuF_YYa7vsr-nEQwsYBBuOjCwhvP6BqTLo')
  const row = { ...claim, payload: null, ...(await signRecordOp(identity, claim, 'test/op', p)) }
  expect(await recordPayloadMatches(row, claim, p)).toBe(true)
  const before = p.hashes.length
  expect((await verifySignedRecord(row, 'test/op', undefined, p))?.contentDigest).toBe(
    'pE0m65URmEuF_YYa7vsr-nEQwsYBBuOjCwhvP6BqTLo',
  )
  expect(p.hashes).toHaveLength(before + 2)
})

test('visibility filtering returns authenticated snapshots when callers replace records during verification', async () => {
  const row = await record()
  const original = structuredClone(row)
  const input = [row]
  const g = gate()
  let entered = () => {}
  const started = new Promise<void>((resolve) => {
    entered = resolve
  })
  const p = provider({
    async verify(...args) {
      entered()
      await g.waiting
      return nobleCrypto.verify(...args)
    },
  })
  const store: RecordStoreAdapter = {
    async get() {
      return null
    },
    async list() {
      return []
    },
    async putCopy() {},
    async pruneCopy() {},
    async transaction(fn) {
      return fn(store)
    },
  }
  const pending = filterVisibleRecords(
    input,
    new Map([
      [
        'test.value',
        {
          type: 'test.value',
          policy: { kind: 'lww' },
          dependsOn: [],
          dependencies: () => [],
          authorize: async () => true,
          visibleTo: visibilityRules(['ownerDevices']),
        },
      ],
    ]),
    {
      ...p,
      opKind: 'test/op',
      requester: { peerDID: identity.id, controllerDID: null },
      proofs: [],
      store,
      authorizeProof: async () => true,
      currentKeyVersion: async () => null,
      isGroupMember: async () => false,
      holderTypes: new Map(),
    },
  )
  await started
  row.payload?.fill(9)
  row.id = 'changed'
  input[0] = { ...row, owner: 'did:key:replacement' }
  g.release()
  expect(await pending).toEqual([original])
})

test('filter key-version policy is captured before signature verification suspends', async () => {
  const claim = { ...claimFixture, meta: { keyID: 'key', keyVersion: 1, recipient: identity.id } }
  const row = { ...(await record()), ...claim, ...(await signRecordOp(identity, claim, 'test/op')) }
  const g = gate()
  let entered = () => {}
  const started = new Promise<void>((resolve) => {
    entered = resolve
  })
  const p = provider({
    async verify(...args) {
      entered()
      await g.waiting
      return nobleCrypto.verify(...args)
    },
  })
  const store: RecordStoreAdapter = {
    async get() {
      return null
    },
    async list() {
      return []
    },
    async putCopy() {},
    async pruneCopy() {},
    async transaction(fn) {
      return fn(store)
    },
  }
  const definition: RecordTypeDefinition = {
    type: 'test.value',
    policy: { kind: 'lww' },
    dependsOn: [],
    dependencies: () => [],
    authorize: async () => true,
    visibleTo: visibilityRules(['keyHolder']),
  }
  const ctx: VisibilityContext = {
    ...p,
    opKind: 'test/op',
    requester: { peerDID: identity.id, controllerDID: null },
    proofs: [row],
    store,
    authorizeProof: async () => true,
    currentKeyVersion: async () => 1,
    isGroupMember: async () => false,
    holderTypes: new Map([['test.value', definition]]),
  }
  const pending = filterVisibleRecords([row], new Map([['test.value', definition]]), ctx)
  await started
  ctx.currentKeyVersion = async () => {
    throw new Error('replacement policy')
  }
  g.release()
  expect(await pending).toHaveLength(1)
})

test('authenticated operations and nested metadata refuse mutation', async () => {
  const claim = { ...claimFixture, meta: { nested: { values: [1, 2] } } }
  const signed = await signRecordOp(identity, claim, 'test/op')
  const op = await verifyRecordOp(signed.opJWT, 'test/op')
  if (op === null) throw new Error('fixture signature did not verify')
  expect(() => {
    op.claim.hlc = 'changed'
  }).toThrow(TypeError)
  expect(() => {
    ;(op.claim.meta.nested as { values: Array<number> }).values.push(3)
  }).toThrow(TypeError)
  expect(() => {
    op.claim = claimFixture
  }).toThrow(TypeError)
  expect(() => {
    op.contentDigest = 'substituted'
  }).toThrow(TypeError)
  expect(() => {
    Object.defineProperty(op, 'contentDigest', { value: 'substituted' })
  }).toThrow(TypeError)
  expect(op.contentDigest).toBe(await recordClaimDigest(claim))
})
