import { nobleCrypto } from '@kokuin/crypto'
import { createSigningIdentity, stringifyToken } from '@kokuin/token'
import type * as SozaiAsync from '@sozai/async'
import { maybeYield } from '@sozai/async'
import { toB64U } from '@sozai/codec'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { checkCapability, checkDelegationChain, createCapability } from '../src/delegation.js'
import type { RevocationRecord } from '../src/revocation.js'
import { createMemoryRevocationBackend, createRevocationChecker } from '../src/revocation.js'
import type { DelegationChainOptions } from '../src/types.js'

vi.mock('@sozai/async', async (importOriginal) => {
  const original = await importOriginal<typeof SozaiAsync>()
  return { ...original, maybeYield: vi.fn(original.maybeYield) }
})

const yieldSpy = vi.mocked(maybeYield)

beforeEach(() => {
  vi.spyOn(globalThis, 'setTimeout')
  vi.spyOn(globalThis, 'setImmediate')
})
afterEach(() => vi.restoreAllMocks())

function clearSchedulingSpies() {
  yieldSpy.mockClear()
  vi.mocked(globalThis.setTimeout).mockClear()
  vi.mocked(globalThis.setImmediate).mockClear()
}

function expectYieldCalls(count: number) {
  expect(yieldSpy).toHaveBeenCalledTimes(count)
  if (count === 0) {
    expect(globalThis.setTimeout).not.toHaveBeenCalled()
    expect(globalThis.setImmediate).not.toHaveBeenCalled()
  }
}

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
        const options: DelegationChainOptions = {
          crypto: { ...nobleCrypto },
          atTime,
          ...policy,
          verifyToken: ({ yield: forwarded }) => {
            expect(forwarded).toBe(policy.yield)
          },
        }
        return entry === 'capability'
          ? checkCapability({ payload: { ...payload, cap: chain }, permission, ...options })
          : checkDelegationChain({ payload, capabilities: chain, ...options })
      }
      clearSchedulingSpies()
      await expect(run(capabilities)).resolves.toBeUndefined()
      expectYieldCalls(policy.yield === false ? 0 : 3)

      // Each position must still be cryptographically checked, including recursive ancestors.
      for (const [index, token] of [leaf, middle, root].entries()) {
        const invalid = [...capabilities]
        invalid[index] = stringifyToken({ ...token, signature: toB64U(new Uint8Array(64)) })
        clearSchedulingSpies()
        await expect(run(invalid)).rejects.toThrow('Invalid signature')
        expectYieldCalls(policy.yield === false ? 0 : index + 1)
      }
      await expect(run(capabilities, 201)).rejects.toThrow('expired')
    })
  }
}

const owner = createSigningIdentity({ privateKey: new Uint8Array(32).fill(41) })
const delegate = createSigningIdentity({ privateKey: new Uint8Array(32).fill(42) })
const permission = { act: 'read', res: 'doc/1' }
const capabilityPayload = { sub: owner.id, aud: delegate.id, ...permission, jti: 'grant' }

async function revocationFixture() {
  const token = await owner.signToken({ payload: capabilityPayload, yield: false })
  const record = await owner.signToken({
    payload: { jti: 'grant', rev: true as const, iat: 100 },
    yield: false,
  })
  return { token, record }
}

for (const policy of [{ yield: false }, { yield: true }, {}]) {
  test(`revocation backend preserves crypto and record checks with yield ${policy.yield}`, async () => {
    const { record } = await revocationFixture()
    const backend = createMemoryRevocationBackend({ crypto: { ...nobleCrypto }, ...policy })
    clearSchedulingSpies()
    await backend.add(record)
    expect(await backend.get({ jti: 'grant', issuer: owner.id })).toEqual(record)
    expectYieldCalls(policy.yield === false ? 0 : 1)

    const invalid = { ...record, signature: toB64U(new Uint8Array(64)) }
    clearSchedulingSpies()
    await expect(backend.add(invalid)).rejects.toThrow('Invalid signature')
    expectYieldCalls(policy.yield === false ? 0 : 1)
    const malformed = await owner.signToken({
      payload: { jti: 'grant', rev: false, iat: 100 },
      yield: false,
    })
    await expect(backend.add(malformed as RevocationRecord)).rejects.toThrow(
      'Invalid revocation record',
    )
  })

  for (const entry of ['checker', 'capability', 'chain'] as const) {
    test(`${entry} revocation checking preserves outcomes with yield ${policy.yield}`, async () => {
      const { token, record } = await revocationFixture()
      const run = (stored: RevocationRecord, configured = entry === 'checker') => {
        const checker = createRevocationChecker({
          backend: { add: async () => {}, get: async () => stored },
          crypto: { ...nobleCrypto },
          ...(configured ? policy : {}),
        })
        if (entry === 'checker') return checker({ token, raw: stringifyToken(token) })
        const payload = { iss: delegate.id, sub: owner.id, aud: owner.id, ...permission }
        const options: DelegationChainOptions = {
          crypto: { ...nobleCrypto },
          verifyToken: checker,
          ...policy,
        }
        return entry === 'capability'
          ? checkCapability({
              payload: { ...payload, cap: [stringifyToken(token)] },
              permission,
              ...options,
            })
          : checkDelegationChain({ payload, capabilities: [stringifyToken(token)], ...options })
      }
      clearSchedulingSpies()
      await expect(run(record)).rejects.toThrow('Token revoked: grant')
      expectYieldCalls(policy.yield === false ? 0 : entry === 'checker' ? 1 : 2)
      clearSchedulingSpies()
      await expect(
        run({ ...record, signature: toB64U(new Uint8Array(64)) }),
      ).resolves.toBeUndefined()
      expectYieldCalls(policy.yield === false ? 0 : entry === 'checker' ? 1 : 2)
      const foreign = await delegate.signToken({
        payload: { jti: 'grant', rev: true as const, iat: 100 },
        yield: false,
      })
      await expect(run(foreign)).resolves.toBeUndefined()
    })
  }

  test(`delegation creation forwards yield ${policy.yield} without changing signed bytes or checks`, async () => {
    const parent = await owner.signToken({ payload: capabilityPayload, yield: false })
    const payload = { sub: owner.id, aud: owner.id, ...permission }
    const run = (parentCapability = stringifyToken(parent), child = payload) => {
      return createCapability({
        signer: delegate,
        payload: child,
        parentCapability,
        crypto: { ...nobleCrypto },
        ...policy,
      })
    }
    clearSchedulingSpies()
    const signed = await run()
    expectYieldCalls(policy.yield === false ? 0 : 2)
    expect(signed).toEqual(await delegate.signToken({ payload, yield: false }))
    clearSchedulingSpies()
    await expect(
      run(stringifyToken({ ...parent, signature: toB64U(new Uint8Array(64)) })),
    ).rejects.toThrow('Invalid signature')
    expectYieldCalls(policy.yield === false ? 0 : 1)
    await expect(run(undefined, { ...payload, act: 'write' })).rejects.toThrow(
      'delegated permission exceeds parent capability',
    )
  })

  test(`member creation forwards yield ${policy.yield} and preserves claim validation`, async () => {
    const payload = { sub: owner.id, aud: owner.id, ...permission, iat: 100, exp: 200 }
    const member = { add: toB64U(new Uint8Array(32).fill(43)), g: 0 }
    clearSchedulingSpies()
    const signed = await createCapability({ signer: delegate, payload, member, ...policy })
    expectYieldCalls(policy.yield === false ? 0 : 1)
    expect(signed).toEqual(
      await delegate.signToken({
        payload: { ...payload, mbr: member },
        yield: false,
      }),
    )
    await expect(
      createCapability({
        signer: delegate,
        payload: { ...payload, exp: 99 },
        member,
        ...policy,
      }),
    ).rejects.toThrow('member grant expires before it is issued')
  })

  test(`root creation forwards yield ${policy.yield}`, async () => {
    clearSchedulingSpies()
    const signed = await createCapability({ signer: owner, payload: capabilityPayload, ...policy })
    expectYieldCalls(policy.yield === false ? 0 : 1)
    expect(signed).toEqual(await owner.signToken({ payload: capabilityPayload, yield: false }))
  })
}

test('revocation hook policy overrides its configured default and omission retains it', async () => {
  const { token, record } = await revocationFixture()
  for (const configured of [false, true]) {
    for (const policy of [{ yield: false }, { yield: true }, {}]) {
      const checker = createRevocationChecker({
        backend: { add: async () => {}, get: async () => record },
        crypto: { ...nobleCrypto },
        yield: configured,
      })
      clearSchedulingSpies()
      await expect(checker({ token, raw: stringifyToken(token), ...policy })).rejects.toThrow(
        'Token revoked: grant',
      )
      expectYieldCalls((policy.yield ?? configured) ? 1 : 0)
    }
  }
})
