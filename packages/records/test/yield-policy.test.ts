import { nobleCrypto } from '@kokuin/crypto'
import { randomIdentity, verifyToken } from '@kokuin/token'
import type * as SozaiAsync from '@sozai/async'
import { fromB64U, toB64U } from '@sozai/codec'
import { beforeEach, expect, test, vi } from 'vitest'

import { clearRecordOpMemo } from '../../records/src/op.js'
import { clearVerifiedSignatureMemo } from '../../token/lib/verified-memo.js'
import type { RecordStoreAdapter, RecordTypeDefinition, VisibilityContext } from '../src/index.js'
import {
  applyRecordChunk,
  createRecordVerifier,
  filterVisibleRecords,
  recordDecisionDigest,
  recordPayloadDigest,
  signRecordOp,
  verifyHolderProof,
  verifyRecordOp,
  verifySignedRecord,
  visibleTo,
} from '../src/index.js'
import { claimFixture } from './crypto-fixture.js'

const timers = vi.hoisted(() =>
  vi.fn((callback: () => void) => {
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
}
beforeEach(clearMemos)

async function fixture() {
  const identity = randomIdentity()
  const claim = {
    ...claimFixture,
    owner: identity.id,
    hlc: '2026-01-01T00:00:00.000Z:00000000:node',
    payloadDigest: null,
    deleted: true,
  }
  const signed = await signRecordOp({ identity, claim, opKind: 'test/yield', yield: false })
  const record = { ...claim, ...signed, payload: null }
  return { identity, claim, signed, record }
}
test('record signing skips timers and preserves signed bytes and claim errors', async () => {
  const f = await fixture()
  expect(timers).not.toHaveBeenCalled()
  expect(
    await signRecordOp({ identity: f.identity, claim: f.claim, opKind: 'test/yield' }),
  ).toEqual(f.signed)
  expect(timers).toHaveBeenCalled()
  for (const policy of [{ yield: false }, {}]) {
    await expect(
      signRecordOp({
        identity: f.identity,
        claim: { ...f.claim, meta: { bad: undefined } },
        opKind: 'test/yield',
        ...policy,
      }),
    ).rejects.toThrow()
  }
})
for (const entry of ['op', 'signed', 'scoped', 'digest', 'visible', 'list', 'apply'] as const) {
  test(`${entry} forwards yield through cold verification and preserves refusals`, async () => {
    const f = await fixture()
    const rows: RecordStoreAdapter = {
      get: async () => null,
      list: async () => [],
      putCopy: async () => {},
      pruneCopy: async () => {},
      transaction: async (fn) => fn(rows),
    }
    const definition: RecordTypeDefinition = {
      type: f.record.type,
      policy: { kind: 'lww' },
      dependsOn: [],
      dependencies: () => [],
      authorize: async () => true,
      visibleTo: async ({ record, ctx }) => visibleTo({ record, ctx, rules: ['ownerDevices'] }),
    }
    const types = new Map([[f.record.type, definition]])
    const run = async (policy: { yield?: boolean }, invalid = false) => {
      const record = invalid ? { ...f.record, owner: 'did:key:wrong' } : f.record
      const options = { opKind: 'test/yield', ...policy }
      const ctx: VisibilityContext = {
        ...options,
        requester: { peerDID: f.identity.id, controllerDID: null },
        proofs: [],
        store: rows,
        holderTypes: new Map(),
        authorizeProof: async () => true,
        currentKeyVersion: async () => null,
        isGroupMember: async () => false,
      }
      switch (entry) {
        case 'op':
          return verifyRecordOp({
            ...options,
            opJWT: f.signed.opJWT,
            opKind: invalid ? 'wrong' : options.opKind,
          })
        case 'signed':
          return verifySignedRecord({ ...options, record })
        case 'scoped':
          return createRecordVerifier(options)(record)
        case 'digest':
          return recordDecisionDigest({ ...options, record })
        case 'visible':
          return visibleTo({ record, ctx, rules: ['ownerDevices'] })
        case 'list':
          return filterVisibleRecords({ records: [record], ctx, types })
        case 'apply':
          return applyRecordChunk({
            ...options,
            records: [record],
            types,
            store: rows,
            nowMS: Date.parse('2026-01-01'),
            maxDriftMS: 1000,
            receiveClock: () => {},
            resolveController: async () => null,
            verifyCapability: async () => false,
          })
      }
    }
    clearMemos()
    const disabled = await run({ yield: false })
    expect(timers).not.toHaveBeenCalled()
    clearMemos()
    expect(await run({})).toEqual(disabled)
    expect(timers).toHaveBeenCalled()
    const outcomes = []
    for (const policy of [{ yield: false }, {}]) {
      clearMemos()
      outcomes.push(
        await run(policy, true).then(
          (value) => ({ value }),
          (error) => ({ error: String(error) }),
        ),
      )
      expect(timers.mock.calls.length > 0).toBe(policy.yield !== false)
    }
    expect(outcomes[0]).toEqual(outcomes[1])
  })
}

test('invalid signatures and provider failures keep their results and errors under both policies', async () => {
  const f = await fixture()
  const parts = f.signed.opJWT.split('.')
  const encodedSignature = parts[2]
  if (encodedSignature === undefined) throw new Error('Missing signature')
  const signature = fromB64U(encodedSignature)
  const first = signature[0]
  if (first === undefined) throw new Error('Empty signature')
  signature[0] = first ^ 1
  parts[2] = toB64U(signature)
  const invalid = parts.join('.')
  const failure = new Error('Crypto provider unavailable')
  const brokenCrypto = {
    ...nobleCrypto,
    verify: async () => {
      throw failure
    },
  }
  for (const policy of [{ yield: false }, {}]) {
    clearMemos()
    expect(await verifyRecordOp({ opJWT: invalid, opKind: 'test/yield', ...policy })).toBeNull()
    expect(timers.mock.calls.length > 0).toBe(policy.yield !== false)
    clearMemos()
    await expect(
      verifyRecordOp({
        opJWT: f.signed.opJWT,
        opKind: 'test/yield',
        crypto: brokenCrypto,
        ...policy,
      }),
    ).rejects.toBe(failure)
    expect(timers.mock.calls.length > 0).toBe(policy.yield !== false)
  }
})

test('scoped verifier captures its policy and memo hits schedule no timer', async () => {
  const f = await fixture()
  const options = { opKind: 'test/yield', yield: false }
  const verify = createRecordVerifier(options)
  options.yield = true
  clearMemos()
  const result = await verify(f.record)
  expect(result).not.toBeNull()
  expect(timers).not.toHaveBeenCalled()
  expect(await verify(f.record)).toEqual(result)
  expect(timers).not.toHaveBeenCalled()
})

test('apply forwards its policy to capability verification hooks', async () => {
  const f = await fixture()
  for (const policy of [{ yield: false }, {}]) {
    const verifyCapability = vi.fn(
      async (options: { tokens: ReadonlyArray<string>; yield?: boolean }) => {
        await verifyToken({ token: f.signed.opJWT, yield: options.yield })
        return true
      },
    )
    const store: RecordStoreAdapter = {
      get: async () => null,
      list: async () => [],
      putCopy: async () => {},
      pruneCopy: async () => {},
      transaction: async (fn) => fn(store),
    }
    const definition: RecordTypeDefinition = {
      type: f.record.type,
      policy: { kind: 'lww' },
      dependsOn: [],
      dependencies: () => [],
      authorize: async ({ ctx }) =>
        ctx.verifyCapability({
          tokens: [f.signed.opJWT],
          owner: f.identity.id,
          issuer: f.identity.id,
        }),
    }
    clearMemos()
    const result = await applyRecordChunk({
      ...policy,
      opKind: 'test/yield',
      records: [f.record],
      store,
      types: new Map([[f.record.type, definition]]),
      nowMS: Date.parse('2026-01-01'),
      maxDriftMS: 1000,
      receiveClock: () => {},
      resolveController: async () => null,
      verifyCapability,
    })
    expect(result.applied).toBe(1)
    expect(verifyCapability).toHaveBeenCalledOnce()
    expect(verifyCapability.mock.calls[0]?.[0].yield).toBe(false)
    expect(timers.mock.calls.length > 0).toBe(policy.yield !== false)
  }
})

test('holder proofs forward the policy through stored rows and dependencies', async () => {
  const f = await fixture()
  const payload = new Uint8Array([1])
  const claim = {
    ...f.claim,
    deleted: false,
    payloadDigest: await recordPayloadDigest({ payload }),
    meta: { keyID: 'key', keyVersion: 1, recipient: f.identity.id },
  }
  const proof = {
    ...claim,
    payload,
    ...(await signRecordOp({ identity: f.identity, claim, opKind: 'test/yield', yield: false })),
  }
  const dependencyClaim = { ...claim, id: 'dependency' }
  const dependency = {
    ...dependencyClaim,
    payload,
    ...(await signRecordOp({
      identity: f.identity,
      claim: dependencyClaim,
      opKind: 'test/yield',
      yield: false,
    })),
  }
  const copies = [proof, dependency]
  const decisions = await Promise.all(
    copies.map(async (record) => ({
      key: { type: record.type, owner: record.owner, id: record.id },
      decisionHLC: record.hlc,
      contentDigest: await recordDecisionDigest({ record, opKind: 'test/yield', yield: false }),
      copies: [record],
    })),
  )
  const store: RecordStoreAdapter = {
    get: async (key) => decisions.find((d) => d.key.id === key.id) ?? null,
    list: async () => decisions,
    putCopy: async () => {},
    pruneCopy: async () => {},
    transaction: async (fn) => fn(store),
  }
  const definition: RecordTypeDefinition = {
    type: proof.type,
    policy: { kind: 'lww' },
    dependsOn: [],
    dependencies: () => [{ type: dependency.type, owner: dependency.owner, id: dependency.id }],
    authorize: async () => true,
  }
  for (const policy of [{ yield: false }, {}]) {
    const ctx: VisibilityContext = {
      ...policy,
      opKind: 'test/yield',
      requester: { peerDID: f.identity.id, controllerDID: null },
      proofs: [proof],
      store,
      holderTypes: new Map([[proof.type, definition]]),
      authorizeProof: async () => true,
      currentKeyVersion: async () => 1,
      isGroupMember: async () => false,
    }
    clearMemos()
    expect(await verifyHolderProof({ proof, ctx })).toBe(true)
    expect(timers.mock.calls.length > 0).toBe(policy.yield !== false)
  }
})

test('apply disables yields in its own transaction but preserves ambient policy', async () => {
  const f = await fixture()
  for (const isTransaction of [false, true]) {
    for (const policy of [undefined, true, false]) {
      const verifyCapability = vi.fn(async (_options: { yield?: boolean }) => true)
      const store: RecordStoreAdapter = {
        isTransaction,
        get: async () => null,
        list: async () => [],
        putCopy: async () => {},
        pruneCopy: async () => {},
        transaction: async (fn) => fn({ ...store, isTransaction: true }),
      }
      const definition: RecordTypeDefinition = {
        type: f.record.type,
        policy: { kind: 'lww' },
        dependsOn: [],
        dependencies: () => [],
        authorize: async ({ ctx }) => {
          expect(ctx.yield).toBe(isTransaction ? policy : false)
          return ctx.verifyCapability({
            tokens: [],
            owner: f.identity.id,
            issuer: f.identity.id,
            yield: true,
          })
        },
      }
      const result = await applyRecordChunk({
        yield: policy,
        opKind: 'test/yield',
        records: [f.record],
        store,
        types: new Map([[f.record.type, definition]]),
        nowMS: Date.parse('2026-01-01'),
        maxDriftMS: 1000,
        receiveClock: () => {},
        resolveController: async () => null,
        verifyCapability,
      })
      expect(result.applied).toBe(1)
      expect(verifyCapability.mock.calls).toHaveLength(1)
      expect(verifyCapability.mock.calls[0]?.[0].yield).toBe(isTransaction ? true : false)
    }
  }
})
