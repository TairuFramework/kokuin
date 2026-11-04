import { type CryptoProvider, nobleCrypto, type SignItem, type VerifyItem } from '@kokuin/crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlnopad } from '@scure/base'
import { beforeEach, expect, test, vi } from 'vitest'

import { canonicalBytes, digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import { createDeviceRevoke, deviceRevokeIndex, deviceRevokeIndices } from '../src/device-revoke.js'
import { TOO_MANY_FAILED_SIGNATURES } from '../src/epoch.js'
import { createAdd, createRemove, createRenew, createRevoke } from '../src/epoch-events.js'
import {
  createInception,
  createReset,
  createRotate,
  didFor,
  didFromInception,
  signEvent,
  verifyInception,
  verifySignatures,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { clearFoldMemo } from '../src/fold-memo.js'
import { authoritativeLog, createMemoryLogStore } from '../src/history.js'
import { createControllerIdentity, createControllerIdentityWithKey } from '../src/identity.js'
import { encodeKey } from '../src/keys.js'
import { provideControllerIdentity } from '../src/keystore-identity.js'
import { MAX_FAILED_SIGNATURES } from '../src/limits.js'
import type { ControllerLog } from '../src/log.js'
import { epochHeads, mergeLogs, pruneLog } from '../src/log.js'
import { enumerateProfiles } from '../src/profiles.js'
import { createControllerResolver } from '../src/resolver.js'
import { resolveBranches } from '../src/supersede.js'

const seed = new Uint8Array(32).fill(19)

function provider(verify?: (items: Array<VerifyItem>) => Promise<Array<boolean>>) {
  const signed: Array<Array<SignItem>> = []
  const verified: Array<Array<VerifyItem>> = []
  const counts = { sign: 0, signBatch: 0, verify: 0, verifyBatch: 0, blake3: 0, blake3Batch: 0 }
  const crypto: CryptoProvider = {
    async sign(...args) {
      counts.sign++
      return nobleCrypto.sign(...args)
    },
    async verify(...args) {
      counts.verify++
      return nobleCrypto.verify(...args)
    },
    async blake3(...args) {
      counts.blake3++
      return nobleCrypto.blake3(...args)
    },
    async blake3Batch(...args) {
      counts.blake3Batch++
      return nobleCrypto.blake3Batch(...args)
    },
    async signBatch(alg, items) {
      counts.signBatch++
      signed.push(structuredClone(items))
      return nobleCrypto.signBatch(alg, items)
    },
    async verifyBatch(items) {
      counts.verifyBatch++
      verified.push(structuredClone(items))
      return verify ? verify(items) : nobleCrypto.verifyBatch(items)
    },
  }
  return { crypto, signed, verified, counts }
}

beforeEach(clearFoldMemo)

test('signing and verification use ordered provider batches over canonical bytes', async () => {
  const p = provider()
  const icp = await createInception(seed, 0, p)
  expect(p.signed).toHaveLength(1)
  expect(p.signed[0]?.[0]?.message).toEqual(canonicalBytes(icp.event))
  const keys = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)]
  const sigs = await signEvent(icp.event, keys, p)
  expect(sigs).toEqual(
    await Promise.all(
      keys.map(async (key) =>
        base64urlnopad.encode(await nobleCrypto.sign('EdDSA', key, canonicalBytes(icp.event))),
      ),
    ),
  )
  expect(p.signed[1]?.map((item) => item.privateKey)).toEqual(keys)
  expect(await verifyInception(icp, didFromInception(icp.event), p)).toBe(true)
  expect(p.verified).toHaveLength(1)
  expect(p.verified[0]?.[0]?.message).toEqual(canonicalBytes(icp.event))
  await createReset(seed, 0, 1, undefined, p)
  expect(p.signed).toHaveLength(3)
  expect(p.counts).toEqual({
    sign: 0,
    signBatch: 3,
    verify: 0,
    verifyBatch: 1,
    blake3: 0,
    blake3Batch: 0,
  })
})

test('provider failures escape verification and folds unchanged and remain retryable', async () => {
  const icp = await createInception(seed, 0)
  const did = didFromInception(icp.event)
  const sentinel = new Error('provider unavailable')
  const p = provider(async () => {
    throw sentinel
  })
  await expect(verifySignatures(icp.event, icp.sigs, icp.event.k, p)).rejects.toBe(sentinel)
  await expect(foldLog(did, { chain: [icp], events: [] }, p)).rejects.toBe(sentinel)
  expect(await verifySignatures(icp.event, ['!'], icp.event.k, p)).toBe(false)
  const history = createMemoryLogStore()
  const resolver = createControllerResolver({
    ...p,
    history,
    loadLog: async () => ({ chain: [icp], events: [] }),
  })
  for (let i = 0; i < 2; i++) await expect(resolver.resolve(did, {})).rejects.toBe(sentinel)
  expect(await history.get(did)).toBeUndefined()
  expect(p.verified).toHaveLength(4)
})

for (const failure of [false, new Error('provider failed')]) {
  for (const withHistory of [false, true]) {
    for (const frozen of [false, true]) {
      test(`fold memo isolates provider policy with history=${withHistory}, frozen=${frozen}, failure=${String(failure)}`, async () => {
        const icp = await createInception(seed, 0)
        const did = didFromInception(icp.event)
        const log: ControllerLog = { chain: [icp], events: [] }
        const permissive = provider(async (items) => items.map(() => true))
        const rejecting = provider(async (items) => {
          if (failure) throw failure
          return items.map(() => false)
        })
        const history = withHistory ? createMemoryLogStore() : undefined
        const first = createControllerResolver({
          ...permissive,
          history,
          loadLog: async () => structuredClone(log),
        })
        await first.resolve(did, {})
        expect(permissive.verified.length).toBeGreaterThan(0)
        const resolver = createControllerResolver({
          ...rejecting,
          history,
          loadLog: async () => structuredClone(log),
        })
        const view = frozen ? resolver.frozen() : resolver
        const outcomes = await Promise.allSettled([view.resolve(did, {}), view.resolve(did, {})])
        expect(outcomes.map((result) => result.status)).toEqual(['rejected', 'rejected'])
        expect(rejecting.verified).toHaveLength(1)
        await expect(view.resolve(did, {})).rejects.toThrow()
        expect(rejecting.verified).toHaveLength(2)
        const second = createControllerResolver({
          ...rejecting,
          history,
          loadLog: async () => structuredClone(log),
        })
        await expect(second.resolve(did, {})).rejects.toThrow()
        expect(rejecting.verified).toHaveLength(3)
      })
    }
  }
}

test('hostile epoch candidates stop at the failed signature budget in causal order', async () => {
  const icp = await createInception(seed, 0)
  const did = didFromInception(icp.event)
  const folded = await foldLog(did, { chain: [icp], events: [] })
  if (!folded.ok) throw new Error(folded.reason)
  const events = await Promise.all(
    Array.from(
      { length: MAX_FAILED_SIGNATURES + 10 },
      async (_, index) =>
        await createRevoke({
          did,
          head: folded.head,
          parents: [folded.head.epoch],
          signer: { root: { seed, profile: 0 } },
          target: `did:key:hostile${index}`,
        }),
    ),
  )
  const p = provider(async (items) =>
    items.map((item) => new TextDecoder().decode(item.message).includes('"t":"icp"')),
  )
  const result = await foldLog(did, { chain: [icp], events: events.toReversed() }, p)
  expect(result).toEqual({ ok: false, reason: TOO_MANY_FAILED_SIGNATURES, index: -1 })
  expect(p.verified).toHaveLength(MAX_FAILED_SIGNATURES + 2)
  const order = events
    .toSorted((a, b) => (digestOf(a.event) < digestOf(b.event) ? -1 : 1))
    .slice(0, MAX_FAILED_SIGNATURES + 1)
  expect(p.verified.slice(1).map((batch) => batch[0]?.message)).toEqual(
    order.map(({ event }) => canonicalBytes(event)),
  )
})

test('profile enumeration stays synchronous without provider operations', () => {
  const methods = ['sign', 'signBatch', 'verify', 'verifyBatch', 'blake3', 'blake3Batch'] as const
  const spies = methods.map((method) =>
    vi.spyOn(nobleCrypto, method).mockImplementation(() => {
      throw new Error('unexpected provider operation')
    }),
  )
  try {
    const entries = enumerateProfiles(seed, 2)
    expect(Array.isArray(entries)).toBe(true)
    expect(entries.map(({ did }) => did)).toEqual([didFor(seed, 0), didFor(seed, 1)])
    expect(spies.every((spy) => spy.mock.calls.length === 0)).toBe(true)
  } finally {
    spies.forEach((spy) => {
      spy.mockRestore()
    })
  }
})

test('root signature sets verify in bounded ordered batches', async () => {
  const icp = await createInception(seed, 0)
  const privateKeys = Array.from({ length: 17 }, (_, index) => new Uint8Array(32).fill(index + 1))
  const keys = privateKeys.map((key) => encodeKey(ed25519.getPublicKey(key), 'EdDSA'))
  const sigs = await signEvent(icp.event, privateKeys)
  const p = provider()
  expect(await verifySignatures(icp.event, sigs, keys, p)).toBe(true)
  expect(p.verified.map((items) => items.length)).toEqual([4, 4, 4, 4, 1])
  expect(p.verified.flat().map((item) => item.publicKey)).toEqual(
    privateKeys.map((key) => ed25519.getPublicKey(key)),
  )
})

test('all controller builders and identity signers retain the selected provider', async () => {
  const p = provider()
  const icp = await createInception(seed, 0, p)
  const did = didFromInception(icp.event)
  const log = { chain: [icp], events: [] }
  const folded = await foldLog(did, log, p)
  if (!folded.ok) throw new Error(folded.reason)
  const base = { ...p, did, head: folded.head, parents: [folded.head.epoch] }
  const signer = { root: { seed, profile: 0 } }
  const key = encodeKey(ed25519.getPublicKey(new Uint8Array(32).fill(2)), 'EdDSA')
  const add = await createAdd({
    ...base,
    seed,
    profile: 0,
    member: { did: `did:key:${key}`, key, lease: 100 },
  })
  await createRenew({ ...base, signer, add: digestOf(add.event), lease: 200 })
  await createRemove({ ...base, signer, add: digestOf(add.event) })
  const rev = await createRevoke({ ...base, signer, target: 'did:key:revoked' })
  await createRotate({
    ...p,
    seed,
    profile: 0,
    did,
    prior: icp.event,
    snapshot: { members: [], deny: [] },
  })
  const revoked = await createDeviceRevoke({
    ...p,
    seed,
    profile: 0,
    did,
    chain: [icp],
    subject: 'did:key:revoked',
  })
  expect(p.signed).toHaveLength(7)
  const identity = await createControllerIdentity({ ...p, seed, profile: 0, log })
  const privateKey = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').privateKey
  const keyed = await createControllerIdentityWithKey({ ...p, privateKey, log })
  await identity.signToken({ example: true })
  await keyed.signToken({ example: true })
  expect(p.counts.sign).toBe(2)
  const history = createMemoryLogStore()
  const provisioned = await provideControllerIdentity({
    ...p,
    profile: 0,
    logStore: history,
    entry: { keyID: 'controller-root', getAsync: async () => seed, provideAsync: async () => seed },
  })
  await provisioned.signToken({ example: true })
  expect(p.counts.sign).toBe(3)
  expect(p.signed).toHaveLength(8)
  const seen = p.verified.length
  expect(await epochHeads(did, { ...log, events: [rev] }, p)).toEqual([digestOf(rev.event)])
  expect(await deviceRevokeIndex(did, [icp, revoked], 'did:key:revoked', p)).toBe(1)
  expect(await deviceRevokeIndices(did, [icp, revoked], 'did:key:revoked', p)).toEqual([1])
  await mergeLogs(did, log, { ...log, events: [rev] }, p)
  await pruneLog(did, { ...log, events: [rev] }, p)
  await resolveBranches(did, [[icp]], p)
  await authoritativeLog({ ...p, did, loaded: log, seen: undefined, context: 'test' })
  expect(p.verified.length).toBeGreaterThan(seen)
})

test('default controller verification refuses message-independent small-order forgeries', async () => {
  const icp = await createInception(seed, 0)
  const identityPoint = new Uint8Array(32)
  identityPoint[0] = 1
  const signature = new Uint8Array(64)
  signature[0] = 1
  const forged = {
    event: { ...icp.event, k: [encodeKey(identityPoint, 'EdDSA')] },
    sigs: [base64urlnopad.encode(signature)],
  }
  const did = didFromInception(forged.event)
  expect(ed25519.verify(signature, canonicalBytes(forged.event), identityPoint)).toBe(true)
  expect(await verifyInception(forged, did)).toBe(false)
  expect(await foldLog(did, { chain: [forged], events: [] })).toEqual({
    ok: false,
    reason: 'invalid inception',
    index: 0,
  })
})

function gatedProvider() {
  let release: () => void = () => {
    throw new Error('verification has not started')
  }
  let started: () => void = () => {
    throw new Error('verification has not started')
  }
  const waiting = new Promise<void>((resolve) => {
    started = resolve
  })
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const p = provider(async (items) => {
    const result = await nobleCrypto.verifyBatch(items)
    started()
    await gate
    return result
  })
  return { ...p, waiting, release: () => release() }
}

test('folds retain authenticated inception, rotate and epoch bytes during suspension', async () => {
  const icp = await createInception(seed, 0)
  const did = didFromInception(icp.event)
  const rotate = await createRotate({
    seed,
    profile: 0,
    did,
    prior: icp.event,
    snapshot: { members: [], deny: [] },
  })
  const folded = await foldLog(did, { chain: [icp, rotate], events: [] })
  if (!folded.ok) throw new Error(folded.reason)
  const revoke = await createRevoke({
    did,
    head: folded.head,
    parents: [folded.head.epoch],
    signer: { root: { seed, profile: 0 } },
    target: 'did:key:original',
  })
  const original = { chain: [icp, rotate], events: [revoke] }
  const expected = await foldLog(did, structuredClone(original))
  const mutableInception = structuredClone(icp)
  const mutableRotate = structuredClone(rotate)
  const log = { chain: [mutableInception, mutableRotate], events: [structuredClone(revoke)] }
  const p = gatedProvider()
  const pending = foldLog(did, log, p)
  await p.waiting
  mutableInception.event.k = [...mutableRotate.event.k]
  mutableRotate.event.d = ['did:key:forged']
  const mutableRevoke = log.events[0]
  if (mutableRevoke === undefined) throw new Error('missing revoke fixture')
  mutableRevoke.event.x = 'did:key:forged'
  p.release()
  expect(await pending).toEqual(expected)
})

test('memo keys, persisted logs and folded state share the authenticated snapshot', async () => {
  const icp = await createInception(seed, 0)
  const did = didFromInception(icp.event)
  const pristine = { chain: [icp], events: [] }
  let loaded = structuredClone(pristine)
  const p = gatedProvider()
  const history = createMemoryLogStore()
  const resolver = createControllerResolver({ ...p, history, loadLog: async () => loaded })
  const pending = resolver.resolve(did, {})
  await p.waiting
  const mutable = loaded.chain[0]
  if (mutable === undefined) throw new Error('missing inception fixture')
  mutable.event.k = (await createInception(seed, 1)).event.k
  p.release()
  const expectedKey = ed25519.getPublicKey(
    deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').privateKey,
  )
  expect(await pending).toEqual({ alg: 'EdDSA', publicKey: expectedKey })
  expect(await history.get(did)).toEqual(pristine)
  loaded = structuredClone(pristine)
  const second = createControllerResolver({ ...p, loadLog: async () => loaded })
  expect(await second.resolve(did, {})).toEqual({ alg: 'EdDSA', publicKey: expectedKey })
})

test('branch winners own the authenticated chain during verification', async () => {
  const icp = await createInception(seed, 0)
  const did = didFromInception(icp.event)
  const pristine = structuredClone(icp)
  const p = gatedProvider()
  const pending = resolveBranches(did, [[icp]], p)
  await p.waiting
  icp.event.k = (await createInception(seed, 1)).event.k
  p.release()
  expect(await pending).toEqual({ ok: true, winner: [pristine], superseded: 0 })
})

test('identity construction captures private material before verification suspends', async () => {
  for (const keyed of [false, true]) {
    const privateSeed = seed.slice()
    const icp = await createInception(privateSeed, 0)
    const did = didFromInception(icp.event)
    const privateKey = deriveKeyPair(privateSeed, authorityPath(0, 0, 0), 'EdDSA').privateKey
    const p = gatedProvider()
    const log = { chain: [icp], events: [] }
    const pending = keyed
      ? createControllerIdentityWithKey({ ...p, privateKey, log })
      : createControllerIdentity({ ...p, seed: privateSeed, profile: 0, log })
    await p.waiting
    privateSeed.fill(0)
    privateKey.fill(0)
    p.release()
    const identity = await pending
    expect(identity.id).toBe(did)
    expect(identity.publicKey).toEqual(
      deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
    )
  }
})

for (const invalidFirst of [true, false]) {
  test(`sixteen signatures stop at the first failed chunk with invalidFirst=${invalidFirst}`, async () => {
    const icp = await createInception(seed, 0)
    const privateKeys = Array.from({ length: 16 }, (_, index) => new Uint8Array(32).fill(index + 1))
    const keys = privateKeys.map((key) => encodeKey(ed25519.getPublicKey(key), 'EdDSA'))
    const sigs = await signEvent(icp.event, privateKeys)
    if (invalidFirst) sigs[0] = base64urlnopad.encode(new Uint8Array(64))
    const p = provider()
    expect(await verifySignatures(icp.event, sigs, keys, p)).toBe(!invalidFirst)
    expect(p.verified.map((items) => items.length)).toEqual(invalidFirst ? [4] : [4, 4, 4, 4])
  })
}
