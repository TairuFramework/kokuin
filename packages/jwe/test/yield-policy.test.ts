import { randomIdentity } from '@kokuin/token'
import type * as SozaiAsync from '@sozai/async'
import { fromB64U, toB64U } from '@sozai/codec'
import { beforeEach, expect, test, vi } from 'vitest'

import { clearRecordOpMemo } from '../../records/lib/op.js'
import { clearVerifiedSignatureMemo } from '../../token/lib/verified-memo.js'
import {
  createTokenEncrypter,
  decryptToken,
  encryptToken,
  unwrapEnvelope,
  wrapEnvelope,
} from '../src/index.js'

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

for (const mode of ['jws', 'jws-in-jwe', 'jwe-in-jws'] as const) {
  test(`${mode} skips timers for signing and verification without changing results or errors`, async () => {
    const signer = randomIdentity()
    const decrypter = randomIdentity()
    const encrypter = createTokenEncrypter({ recipient: decrypter.id })
    const params = { mode, payload: { value: 42 }, signer, encrypter }
    const message = await wrapEnvelope({ ...params, yield: false })
    expect(timers).not.toHaveBeenCalled()
    const normal = await wrapEnvelope(params)
    expect(timers).toHaveBeenCalled()
    if (mode === 'jws') expect(normal).toBe(message)
    clearMemos()
    const result = await unwrapEnvelope({ message, decrypter, yield: false })
    expect(timers).not.toHaveBeenCalled()
    clearMemos()
    expect(await unwrapEnvelope({ message, decrypter })).toEqual(result)
    expect(timers).toHaveBeenCalled()
    const jws =
      mode === 'jws-in-jwe'
        ? new TextDecoder().decode(await decryptToken({ jwe: message, decrypter }))
        : message
    const parts = jws.split('.')
    const encodedSignature = parts[2]
    if (encodedSignature === undefined) throw new Error('Missing signature')
    const signature = fromB64U(encodedSignature)
    const first = signature[0]
    if (first === undefined) throw new Error('Empty signature')
    signature[0] = first ^ 1
    parts[2] = toB64U(signature)
    const corrupt =
      mode === 'jws-in-jwe'
        ? await encryptToken({ encrypter, plaintext: new TextEncoder().encode(parts.join('.')) })
        : parts.join('.')
    const errors = []
    for (const policy of [{ yield: false }, {}]) {
      clearMemos()
      errors.push(
        await unwrapEnvelope({ message: corrupt, decrypter, ...policy }).then(
          () => null,
          (error) => String(error),
        ),
      )
      expect(timers.mock.calls.length > 0).toBe(policy.yield !== false)
    }
    expect(errors[0]).not.toBeNull()
    expect(errors[0]).toEqual(errors[1])
    const expired = await wrapEnvelope({ ...params, payload: { exp: 1 }, yield: false })
    for (const policy of [{ yield: false }, {}]) {
      clearMemos()
      // jwe-in-jws's payload is encrypted; time claims belong to its outer JWS only.
      if (mode !== 'jwe-in-jws')
        await expect(unwrapEnvelope({ message: expired, decrypter, ...policy })).rejects.toThrow(
          'Token expired',
        )
    }
  })
}
