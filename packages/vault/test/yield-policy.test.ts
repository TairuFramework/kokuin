import { recordDecisionDigest } from '@kokuin/records'
import { randomIdentity } from '@kokuin/token'
import type * as SozaiAsync from '@sozai/async'
import { beforeEach, expect, test, vi } from 'vitest'

import { clearRecordOpMemo } from '../../records/lib/op.js'
import { clearVerifiedSignatureMemo } from '../../token/lib/verified-memo.js'
import { vaultKeyVersionReader, vaultRecordTypes } from '../src/index.js'
import { chain, memoryStore, OP_KIND, verified } from './record-fixture.js'

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

test('vault key version reads forward yield and preserve invalid record refusal', async () => {
  const signer = randomIdentity()
  const f = await chain(signer)
  const digest = await recordDecisionDigest({ record: f.key, opKind: OP_KIND })
  const decision = {
    key: { type: f.key.type, owner: f.owner, id: f.keyID },
    decisionHLC: f.key.hlc,
    contentDigest: digest,
    copies: [f.key],
  }
  for (const invalid of [false, true]) {
    const store = {
      get: async () => ({ ...decision, copies: [invalid ? { ...f.key, opHash: 'wrong' } : f.key] }),
      list: async () => [],
      putCopy: async () => {},
      pruneCopy: async () => {},
      transaction: async () => {
        throw new Error('unused')
      },
    }
    for (const policy of [{ yield: false }, {}]) {
      const read = vaultKeyVersionReader({ store, opKind: OP_KIND, ...policy })
      clearMemos()
      expect(await read({ owner: f.owner, keyID: f.keyID })).toBe(invalid ? null : 1)
      expect(timers.mock.calls.length > 0).toBe(policy.yield !== false)
    }
  }
})

test('a scope yield accessor follows the current store without changing verification', async () => {
  const signer = randomIdentity()
  const f = await chain(signer)
  const digest = await recordDecisionDigest({ record: f.key, opKind: OP_KIND, yield: false })
  let policy = true
  const read = vaultKeyVersionReader({
    opKind: OP_KIND,
    get yield() {
      return policy
    },
    store: {
      get: async () => ({
        key: { type: f.key.type, owner: f.owner, id: f.keyID },
        decisionHLC: f.key.hlc,
        contentDigest: digest,
        copies: [f.key],
      }),
      list: async () => [],
      putCopy: async () => {},
      pruneCopy: async () => {},
      transaction: async () => {
        throw new Error('unused')
      },
    },
  })
  for (const scoped of [false, true, false]) {
    policy = scoped
    clearMemos()
    expect(await read({ owner: f.owner, keyID: f.keyID })).toBe(1)
    expect(timers.mock.calls.length > 0).toBe(scoped)
  }
})

for (const captured of [undefined, true, false]) {
  for (const override of [undefined, false, true]) {
    test(`vault record hooks: captured=${captured}, override=${override}`, async () => {
      const signer = randomIdentity()
      const f = await chain(signer)
      const { store, hooks } = memoryStore()
      const op = await verified(f.key)
      for (const allowed of [true, false]) {
        const types = vaultRecordTypes({
          ...hooks,
          authority: { authorize: async () => allowed },
          opKind: OP_KIND,
          yield: captured,
        })
        const key = types.get('vault.key')
        if (key?.visibleTo === undefined) throw new Error('Missing key hooks')
        clearMemos()
        expect(
          await key.authorize({
            op,
            ctx: {
              record: f.key,
              stored: null,
              store,
              yield: override,
              resolveController: async () => null,
              verifyCapability: async () => false,
            },
          }),
        ).toBe(allowed)
        expect.soft(timers.mock.calls.length > 0).toBe((override ?? captured) !== false)
        clearMemos()
        expect(
          await key.visibleTo({
            record: f.key,
            ctx: {
              opKind: OP_KIND,
              yield: override,
              store,
              requester: { peerDID: signer.id, controllerDID: null },
              proofs: [],
              holderTypes: types,
              authorizeProof: async () => true,
              currentKeyVersion: async () => 1,
              isGroupMember: async () => false,
            },
          }),
        ).toBe(allowed)
        expect.soft(timers.mock.calls.length > 0).toBe((override ?? captured) !== false)
      }
    })
  }
}
