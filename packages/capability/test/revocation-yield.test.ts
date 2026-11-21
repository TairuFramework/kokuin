import { randomIdentity, verifyToken } from '@kokuin/token'
import type * as SozaiAsync from '@sozai/async'
import { beforeEach, expect, test, vi } from 'vitest'

import { clearRecordOpMemo } from '../../records/src/op.js'
import { clearVerifiedSignatureMemo } from '../../token/src/verified-memo.js'
import { createRevocationRecord } from '../src/index.js'

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

test('revocation creation forwards yield and preserves the signed claims', async () => {
  const signer = randomIdentity()
  vi.spyOn(Date, 'now').mockReturnValue(1800000000000)
  try {
    const disabled = await createRevocationRecord({ signer, jti: 'revoked-token', yield: false })
    expect(timers).not.toHaveBeenCalled()
    expect(await createRevocationRecord({ signer, jti: 'revoked-token' })).toEqual(disabled)
    expect(timers).toHaveBeenCalled()
    expect((await verifyToken({ token: disabled, yield: false })).payload).toMatchObject({
      jti: 'revoked-token',
      rev: true,
      iss: signer.id,
    })
  } finally {
    vi.restoreAllMocks()
  }
})
