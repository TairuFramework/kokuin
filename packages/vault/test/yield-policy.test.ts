import { recordDecisionDigest } from '@kokuin/records'
import { randomIdentity } from '@kokuin/token'
import type * as SozaiAsync from '@sozai/async'
import { beforeEach, expect, test, vi } from 'vitest'

import { clearRecordOpMemo } from '../../records/src/op.js'
import { clearVerifiedSignatureMemo } from '../../token/src/verified-memo.js'
import { vaultKeyVersionReader } from '../src/index.js'
import { chain, OP_KIND } from './record-fixture.js'

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
