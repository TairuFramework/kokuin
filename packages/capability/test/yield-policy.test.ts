import { nobleCrypto } from '@kokuin/crypto'
import { createSigningIdentity, stringifyToken } from '@kokuin/token'
import type * as SozaiAsync from '@sozai/async'
import { maybeYield } from '@sozai/async'
import { toB64U } from '@sozai/codec'
import { expect, test, vi } from 'vitest'

import { checkCapability, checkDelegationChain } from '../src/delegation.js'
import type { DelegationChainOptions } from '../src/types.js'

vi.mock('@sozai/async', async (importOriginal) => {
  const original = await importOriginal<typeof SozaiAsync>()
  return { ...original, maybeYield: vi.fn(original.maybeYield) }
})

const yieldSpy = vi.mocked(maybeYield)

for (const entry of ['capability', 'chain'] as const) {
  for (const policy of [{ yield: false }, { yield: true }, {}]) {
    test(`${entry} forwards yield ${policy.yield} through every real-crypto chain link`, async () => {
      const identities = [31, 32, 33, 34].map((byte) => {
        return createSigningIdentity({ privateKey: new Uint8Array(32).fill(byte) })
      })
      const [owner, manager, device, holder] = identities
      if (!owner || !manager || !device || !holder) throw new Error('Missing identity')
      const permission = { act: 'read', res: 'doc/1' }
      const root = await owner.signToken({
        payload: { sub: owner.id, aud: manager.id, act: '*', res: '*', exp: 300 },
        yield: false,
      })
      const middle = await manager.signToken({
        payload: { sub: owner.id, aud: device.id, act: 'read', res: '*', exp: 250 },
        yield: false,
      })
      const leaf = await device.signToken({
        payload: { sub: owner.id, aud: holder.id, ...permission, exp: 200 },
        yield: false,
      })
      const capabilities = [leaf, middle, root].map((token) => stringifyToken(token))
      const payload = { iss: holder.id, sub: owner.id, aud: owner.id, ...permission, exp: 150 }
      const run = (chain: Array<string>, atTime = 100) => {
        // A fresh real provider scope forces cache misses on every run.
        const options: DelegationChainOptions = { crypto: { ...nobleCrypto }, atTime, ...policy }
        return entry === 'capability'
          ? checkCapability({ payload: { ...payload, cap: chain }, permission, ...options })
          : checkDelegationChain({ payload, capabilities: chain, ...options })
      }
      yieldSpy.mockClear()
      await expect(run(capabilities)).resolves.toBeUndefined()
      expect(yieldSpy).toHaveBeenCalledTimes(policy.yield === false ? 0 : 3)

      // Each position must still be cryptographically checked, including recursive ancestors.
      for (const [index, token] of [leaf, middle, root].entries()) {
        const invalid = [...capabilities]
        invalid[index] = stringifyToken({ ...token, signature: toB64U(new Uint8Array(64)) })
        yieldSpy.mockClear()
        await expect(run(invalid)).rejects.toThrow('Invalid signature')
        expect(yieldSpy).toHaveBeenCalledTimes(policy.yield === false ? 0 : index + 1)
      }
      await expect(run(capabilities, 201)).rejects.toThrow('expired')
    })
  }
}
