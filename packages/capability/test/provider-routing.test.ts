import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { CODECS, createSigningIdentity, getDID, stringifyToken } from '@kokuin/token'
import { b64uFromJSON, toB64U } from '@sozai/codec'
import { expect, test } from 'vitest'

import { checkCapability, checkDelegationChain, createCapability } from '../src/delegation.js'
import {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
} from '../src/revocation.js'
import type { CapabilityPayload } from '../src/types.js'

function provider(result: boolean | Error = true) {
  let calls = 0
  const crypto: CryptoProvider = {
    ...nobleCrypto,
    async verify() {
      calls++
      if (result instanceof Error) throw result
      return result
    },
  }
  return { crypto, count: () => calls }
}

async function fixture() {
  const owner = createSigningIdentity({ privateKey: new Uint8Array(32).fill(71) })
  const delegate = createSigningIdentity({ privateKey: new Uint8Array(32).fill(72) })
  const recipient = createSigningIdentity({ privateKey: new Uint8Array(32).fill(73) })
  const root = await createCapability({
    signer: owner,
    payload: {
      sub: owner.id,
      aud: delegate.id,
      act: '*',
      res: '*',
      jti: 'root',
    },
  })
  return { owner, delegate, recipient, root, raw: stringifyToken(root) }
}

test('parent creation, direct chains and capability checks forward the provider', async () => {
  const { owner, delegate, recipient, raw } = await fixture()
  const routed = provider()
  const child = await createCapability({
    signer: delegate,
    payload: { sub: owner.id, aud: recipient.id, act: 'read', res: '*' },
    header: undefined,
    parentCapability: raw,
    crypto: routed.crypto,
  })
  expect(routed.count()).toBe(1)
  const chainProvider = provider()
  await checkDelegationChain({
    payload: child.payload,
    capabilities: [raw],
    crypto: chainProvider.crypto,
  })
  expect(chainProvider.count()).toBe(1)
  const leafProvider = provider()
  await checkCapability({
    permission: { act: 'read', res: '*' },
    payload: { iss: recipient.id, sub: owner.id, cap: [stringifyToken(child), raw] },
    crypto: leafProvider.crypto,
  })
  expect(leafProvider.count()).toBe(2)
  const rejected = provider(false)
  await expect(
    createCapability({
      signer: delegate,
      payload: { sub: owner.id, aud: recipient.id, act: 'read', res: '*' },
      header: undefined,
      parentCapability: raw,
      crypto: rejected.crypto,
    }),
  ).rejects.toThrow('Invalid signature')
  await expect(
    checkDelegationChain({
      payload: child.payload,
      capabilities: [raw],
      crypto: rejected.crypto,
    }),
  ).rejects.toThrow('Invalid signature')
  await expect(
    checkCapability({
      permission: { act: 'read', res: '*' },
      payload: { iss: recipient.id, sub: owner.id, cap: raw },
      crypto: rejected.crypto,
    }),
  ).rejects.toThrow('Invalid signature')
  expect(rejected.count()).toBe(3)
})

test('revocation factories capture provider options and verify independently', async () => {
  const { owner, root } = await fixture()
  const record = await createRevocationRecord({ signer: owner, jti: 'root' })
  const routed = provider()
  const options = { crypto: routed.crypto }
  const backend = createMemoryRevocationBackend(options)
  options.crypto = provider(false).crypto
  await backend.add(record)
  expect(routed.count()).toBe(1)
  const checked = provider()
  const checker = createRevocationChecker({ backend, crypto: checked.crypto })
  await expect(checker({ token: root, raw: stringifyToken(root) })).rejects.toThrow('Token revoked')
  expect(checked.count()).toBe(1)
  const failed = provider(false)
  await expect(
    createMemoryRevocationBackend({ crypto: failed.crypto }).add(record),
  ).rejects.toThrow('Invalid signature')
  await expect(
    createRevocationChecker({ backend, crypto: failed.crypto })({
      token: root,
      raw: '',
    }),
  ).resolves.toBeUndefined()
  expect(failed.count()).toBe(2)
})

test('provider operational failures propagate identically through every refusal boundary', async () => {
  const { owner, delegate, recipient, root, raw } = await fixture()
  const record = await createRevocationRecord({ signer: owner, jti: 'root' })
  const sentinel = new Error('provider offline')
  const routed = provider(sentinel)
  const options = { crypto: routed.crypto }
  await expect(
    createCapability({
      signer: delegate,
      payload: { sub: owner.id, aud: recipient.id, act: 'read', res: '*' },
      header: undefined,
      ...options,
      parentCapability: raw,
    }),
  ).rejects.toBe(sentinel)
  await expect(
    checkDelegationChain({
      payload: { ...root.payload, iss: delegate.id },
      capabilities: [raw],
      ...options,
    }),
  ).rejects.toBe(sentinel)
  const backend = {
    async add() {},
    async get() {
      return record
    },
  }
  for (let i = 0; i < 2; i++) {
    await expect(createMemoryRevocationBackend(options).add(record)).rejects.toBe(sentinel)
    await expect(
      createRevocationChecker({ backend, ...options })({ token: root, raw: '' }),
    ).rejects.toBe(sentinel)
  }
  expect(routed.count()).toBe(6)
})

test('ZIP-215-only capabilities and revocations fail strict default verification', async () => {
  const key = new Uint8Array(32)
  key[0] = 1
  const signature = new Uint8Array(64)
  signature[0] = 1
  const did = getDID({ codec: CODECS.EdDSA, publicKey: key })
  const delegate = createSigningIdentity({ privateKey: new Uint8Array(32).fill(74) })
  const header = { typ: 'JWT' as const, alg: 'EdDSA' as const }
  const payload: CapabilityPayload = {
    iss: did,
    sub: did,
    aud: delegate.id,
    act: '*',
    res: '*',
    jti: 'forged',
  }
  const raw = `${b64uFromJSON(header)}.${b64uFromJSON(payload)}.${toB64U(signature)}`
  await expect(
    checkDelegationChain({ payload: { ...payload, iss: delegate.id }, capabilities: [raw] }),
  ).rejects.toThrow('Invalid signature')
  await expect(
    checkCapability({
      permission: { act: 'read', res: '*' },
      payload: { iss: delegate.id, sub: did, cap: raw },
    }),
  ).rejects.toThrow('Invalid signature')
  const record = {
    header,
    payload: { iss: did, rev: true as const, jti: 'forged', iat: 1 },
    signature: toB64U(signature),
  }
  const recordData = `${b64uFromJSON(header)}.${b64uFromJSON(record.payload)}`
  const signedRecord = { ...record, data: recordData }
  await expect(createMemoryRevocationBackend().add(signedRecord)).rejects.toThrow(
    'Invalid signature',
  )
  const backend = {
    async add() {},
    async get() {
      return signedRecord
    },
  }
  await expect(
    createRevocationChecker({ backend })({
      token: {
        header,
        payload,
        data: raw.slice(0, raw.lastIndexOf('.')),
        signature: toB64U(signature),
      },
      raw: '',
    }),
  ).resolves.toBeUndefined()
})

test('a suspended chain retains its captured provider and override policy', async () => {
  const { owner, delegate, recipient, raw } = await fixture()
  const child = await createCapability({
    signer: delegate,
    payload: { sub: owner.id, aud: recipient.id, act: 'read', res: '*' },
    header: undefined,
    parentCapability: raw,
  })
  const routed = provider()
  const rejected = provider(false)
  const options = { crypto: routed.crypto, verifiers: { ES256: () => false } }
  const pending = checkCapability({
    permission: { act: 'read', res: '*' },
    payload: { iss: recipient.id, sub: owner.id, cap: [stringifyToken(child), raw] },
    ...options,
  })
  options.crypto = rejected.crypto
  await expect(pending).resolves.toBeUndefined()
  expect(routed.count()).toBe(2)
  expect(rejected.count()).toBe(0)
})

test('concurrent revocation verification preserves batch operational failures', async () => {
  const { owner } = await fixture()
  const records = await Promise.all([
    createRevocationRecord({ signer: owner, jti: 'first' }),
    createRevocationRecord({ signer: owner, jti: 'second' }),
  ])
  const sentinel = new Error('batch offline')
  let batches = 0
  let singles = 0
  const crypto: CryptoProvider = {
    ...nobleCrypto,
    async verify(...args) {
      singles++
      return nobleCrypto.verify(...args)
    },
    async verifyBatch() {
      batches++
      throw sentinel
    },
  }
  const backend = createMemoryRevocationBackend({ crypto })
  for (let attempt = 0; attempt < 2; attempt++) {
    const results = await Promise.allSettled(records.map((record) => backend.add(record)))
    expect(results).toEqual(records.map(() => ({ status: 'rejected', reason: sentinel })))
  }
  expect(batches).toBe(2)
  expect(singles).toBe(0)
  expect(await backend.get({ jti: 'first', issuer: owner.id })).toBeUndefined()
  const tokens = await Promise.all(
    records.map((record) => {
      return createCapability({
        signer: owner,
        payload: {
          sub: owner.id,
          aud: owner.id,
          act: '*',
          res: '*',
          jti: record.payload.jti,
        },
      })
    }),
  )
  const checker = createRevocationChecker({
    backend: {
      async add() {},
      async get({ jti }) {
        return records.find((record) => record.payload.jti === jti)
      },
    },
    crypto,
  })
  for (let attempt = 0; attempt < 2; attempt++) {
    expect(
      await Promise.allSettled(
        tokens.map((token) => checker({ token, raw: stringifyToken(token) })),
      ),
    ).toEqual(tokens.map(() => ({ status: 'rejected', reason: sentinel })))
  }
  expect(batches).toBe(4)
  expect(singles).toBe(0)
})
