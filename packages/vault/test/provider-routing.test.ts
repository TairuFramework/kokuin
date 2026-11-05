import type { CryptoProviderBlake3Params } from '@kokuin/crypto'
import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { recordPayloadDigest } from '@kokuin/records'
import { createFullIdentity } from '@kokuin/token'
import { toB64U } from '@sozai/codec'
import { expect, test, vi } from 'vitest'

import {
  checkDescriptorDigest,
  descriptorDigest,
  digestParts,
  vaultEntriesDigest,
  vaultEntryDigest,
  vaultKeyDigest,
  vaultWrappingDigest,
} from '../src/digest.js'
import { createVaultKeyID, createVaultKeyReference } from '../src/id.js'
import {
  decodeVaultRecord,
  encodeVaultRecordPayload,
  VaultRecordPayloadError,
  vaultRecordMeta,
} from '../src/records.js'

const descriptors = () => [{ kind: 'passphrase', params: { salt: '刻印', m: 8, t: 1, p: 1 } }]
const entry = { entryID: 'b', iv: 'iv', ciphertext: 'cipher', hlc: 'hlc' }
const KEY_ID = 'k8y7qh91tdnm6bk0xhgwln0vpann3gcosl73c5gtpxjue3in4t8ctzbz8'
const DESCRIPTOR = '2bWLzB_riFaSXTBPOj6aVVxewD7FjIy7pOcW5LXdpfo'

function delayed() {
  let release = () => {}
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const blake3 = vi.fn(async ({ input, dkLen: length }: CryptoProviderBlake3Params) => {
    await gate
    return nobleCrypto.blake3({ input, dkLen: length })
  })
  return { crypto: { ...nobleCrypto, blake3 }, release }
}

test('all vault hashes and key references retain literal golden bytes through single provider calls', async () => {
  const blake3 = vi.fn(nobleCrypto.blake3)
  const blake3Batch = vi.fn(nobleCrypto.blake3Batch)
  const options = { crypto: { ...nobleCrypto, blake3, blake3Batch } }
  expect(await digestParts({ parts: ['刻印', 'a:b', ''], ...options })).toBe(
    'yWcBbIRt_app6n7bWIo8Xv9zV90bCuQ0l8U5eZvCyRg',
  )
  expect(
    await vaultKeyDigest({
      key: { ownerDID: 'did:example:owner', suite: 1, version: 2, state: 'active' },
      ...options,
    }),
  ).toBe('gqV1hD957QHJe3QMr3CxQr3nxPIh3cPrRdgPvu1aIRw')
  expect(
    await vaultWrappingDigest({
      wrapping: {
        wrappingID: 'wrap',
        recipientDID: null,
        iv: 'iv',
        wrappedKey: 'key',
        factors: descriptors(),
      },
      ...options,
    }),
  ).toBe('WjxStCLpem46tNYAc7nEMu13Tc1KTVpnOfU9mT_TGXw')
  expect(
    await vaultEntriesDigest({
      entries: [entry, { entryID: 'a', iv: '', ciphertext: '', hlc: 'x' }],
      ...options,
    }),
  ).toBe('YRhXviKAqoARg43-a_t_lAyaCPYAJpjdFbLHwP8YyZw')
  expect(await vaultEntryDigest({ entry, ...options })).toBe(
    'Sjp4M5xFUE2SrzytuadB0n1fQ1cJugC7GRnDStzaT_I',
  )
  expect(await descriptorDigest({ descriptors: descriptors(), ...options })).toBe(DESCRIPTOR)
  await checkDescriptorDigest({
    descriptors: descriptors(),
    expectedDescriptorDigest: DESCRIPTOR,
    ...options,
  })
  expect(
    await createVaultKeyID({
      owner: 'did:example:owner',
      unique: new Uint8Array(16).fill(7),
      ...options,
    }),
  ).toBe(KEY_ID)
  expect(
    await createVaultKeyReference({
      owner: 'did:example:owner',
      unique: new Uint8Array(16).fill(7),
      ...options,
    }),
  ).toEqual({ keyID: KEY_ID, keyUnique: 'BwcHBwcHBwcHBwcHBwcHBw' })
  expect(blake3).toHaveBeenCalledTimes(9)
  expect(blake3Batch).not.toHaveBeenCalled()
})

test('key reference snapshots Buffer subviews and unique encoding before suspension', async () => {
  const { crypto, release } = delayed()
  const owner = Buffer.from('did:example:owner')
  const backing = Buffer.alloc(18, 7)
  const unique = backing.subarray(1, 17)
  const id = createVaultKeyID({ owner, unique, crypto })
  const reference = createVaultKeyReference({
    owner: 'did:example:owner',
    unique,
    crypto,
  })
  owner.fill(0)
  unique.fill(0)
  release()
  expect(await id).toBe(KEY_ID)
  expect(await reference).toEqual({ keyID: KEY_ID, keyUnique: 'BwcHBwcHBwcHBwcHBwcHBw' })
})

test('descriptor validation captures both descriptors and expected digest before suspension', async () => {
  const { crypto, release } = delayed()
  const params = { descriptors: descriptors(), expectedDescriptorDigest: DESCRIPTOR, crypto }
  const result = checkDescriptorDigest(params)
  const descriptor = params.descriptors[0]
  if (descriptor === undefined) throw new Error('Missing descriptor')
  descriptor.params.salt = 'changed'
  params.expectedDescriptorDigest = 'changed'
  release()
  await expect(result).resolves.toBeUndefined()
})

async function keyFixture() {
  const owner = createFullIdentity({ privateKey: new Uint8Array(32).fill(9) }).id
  const unique = new Uint8Array(16).fill(7)
  const id = await createVaultKeyID({ owner, unique })
  const payload = encodeVaultRecordPayload({
    type: 'vault.key',
    payload: { suite: 1, state: 'active' },
  })
  const meta = {
    keyID: id,
    keyUnique: toB64U(unique),
    version: 1,
    state: 'active',
    consumer: { name: 'original' },
  }
  const record = {
    type: 'vault.key',
    id,
    owner,
    hlc: '2026-11-04T00:00:00.000Z-0000-node',
    payload,
  }
  const claim = {
    ...record,
    deleted: false,
    meta,
    payloadDigest: await recordPayloadDigest({ payload }),
  }
  return { record, claim, meta }
}

test('public metadata validation captures commitment and nested metadata before provider suspension', async () => {
  const fixture = await keyFixture()
  const { crypto, release } = delayed()
  const result = vaultRecordMeta({ type: 'vault.key', claim: fixture.claim, crypto })
  fixture.meta.consumer.name = 'changed'
  fixture.meta.keyUnique = toB64U(new Uint8Array(16))
  fixture.claim.id = KEY_ID
  release()
  expect(await result).toEqual({
    ...fixture.meta,
    keyUnique: 'BwcHBwcHBwcHBwcHBwcHBw',
    consumer: { name: 'original' },
  })
  expect(crypto.blake3).toHaveBeenCalledTimes(1)
})

test('decoding snapshots payload and metadata and forwards provider to both hashes', async () => {
  const fixture = await keyFixture()
  const { crypto, release } = delayed()
  const result = decodeVaultRecord({
    record: fixture.record,
    recordMeta: fixture.meta,
    crypto,
  })
  fixture.record.payload.fill(0)
  fixture.meta.consumer.name = 'changed'
  release()
  const decoded = await result
  expect(decoded.meta.consumer).toEqual({ name: 'original' })
  expect(decoded.payload).toEqual({ suite: 1, state: 'active' })
  expect(crypto.blake3).toHaveBeenCalledTimes(2)
})

test('provider rejection escapes decoding unchanged', async () => {
  const fixture = await keyFixture()
  const sentinel = new Error('provider unavailable')
  const crypto: CryptoProvider = {
    ...nobleCrypto,
    blake3: async () => {
      throw sentinel
    },
  }
  await expect(
    decodeVaultRecord({ record: fixture.record, recordMeta: fixture.meta, crypto }),
  ).rejects.toBe(sentinel)
})

test.each(['cyclic', 'bigint'])('decoding wraps %s metadata snapshot failures', async (kind) => {
  const fixture = await keyFixture()
  const meta: Record<string, unknown> = { ...fixture.meta }
  meta.consumer = kind === 'cyclic' ? meta : { value: 1n }
  const blake3 = vi.fn(nobleCrypto.blake3)
  const outcome = await decodeVaultRecord({
    record: fixture.record,
    recordMeta: meta,
    crypto: { ...nobleCrypto, blake3 },
  }).catch((error: unknown) => error)

  expect(outcome).toBeInstanceOf(VaultRecordPayloadError)
  expect(outcome).toMatchObject({ cause: expect.any(TypeError) })
  expect(blake3).not.toHaveBeenCalled()
})

test('wrong owner commitment refuses metadata', async () => {
  const fixture = await keyFixture()
  fixture.claim.owner = createFullIdentity({ privateKey: new Uint8Array(32).fill(8) }).id
  expect(await vaultRecordMeta({ type: 'vault.key', claim: fixture.claim })).toBeNull()
})

test('every provider rejection escapes vault record authorisation and proof decoding', async () => {
  const { chain, dependent, memoryStore, verified } = await import('./record-fixture.js')
  const { vaultRecordTypes, vaultProofAuthorizer } = await import('../src/record-types.js')
  const signer = createFullIdentity({ privateKey: new Uint8Array(32).fill(12) })
  const source = await chain(signer)
  const record = await dependent({ signer, source, type: 'vault.wrapping' })
  const op = await verified(record)
  const peer = memoryStore()
  await peer.apply([source.key, source.branch])
  const sentinel = new Error('authorisation provider failed')
  let completed = false
  for (let rejectAt = 1; rejectAt < 32; rejectAt++) {
    let calls = 0
    const crypto = {
      ...nobleCrypto,
      blake3: async ({ input, dkLen: length }: CryptoProviderBlake3Params) => {
        if (++calls === rejectAt) throw sentinel
        return nobleCrypto.blake3({ input, dkLen: length })
      },
    }
    const params = {
      ...peer.hooks,
      portsFor: () => {
        return {
          retainEntryCandidate: async () => {},
          listRevocations: async () => [],
          dropRevokedWrappings: async () => {},
        }
      },
      opKind: 'kokuin/vault-op/v1',
      crypto,
    }
    const definition = vaultRecordTypes(params).get('vault.wrapping')
    if (definition === undefined) throw new Error('Missing wrapping definition')
    const authorise = definition.authorize({
      op,
      ctx: {
        record,
        stored: null,
        store: peer.store,
        transportContext: undefined,
        resolveController: async () => null,
        verifyCapability: async () => false,
      },
    })
    const [outcome] = await Promise.allSettled([authorise])
    if (outcome === undefined) throw new Error('Missing authorisation outcome')
    if (calls >= rejectAt) {
      expect(calls).toBe(rejectAt)
      expect(outcome.status).toBe('rejected')
      if (outcome.status === 'rejected') expect(outcome.reason).toBe(sentinel)
    } else {
      expect(outcome).toEqual({ status: 'fulfilled', value: true })
      completed = true
      break
    }
  }
  expect(completed).toBe(true)
  const crypto = {
    ...nobleCrypto,
    verify: async () => {
      throw sentinel
    },
  }
  const proof = vaultProofAuthorizer({
    ...peer.hooks,
    opKind: 'kokuin/vault-op/v1',
    crypto,
    store: peer.store,
  })
  await expect(proof({ record, stored: null })).rejects.toBe(sentinel)
})

test('record factories capture ordinary resolver options at construction', async () => {
  const { createSigningIdentityForDID } = await import('@kokuin/token')
  const { chain } = await import('./record-fixture.js')
  const { verifySignedRecord } = await import('@kokuin/records')
  const { vaultRecordTypes } = await import('../src/record-types.js')
  const signer = createSigningIdentityForDID({
    id: 'did:test:owner',
    privateKey: new Uint8Array(32).fill(23),
  })
  const source = await chain(signer)
  const method = {
    method: 'test',
    resolve: async () => ({ alg: 'EdDSA' as const, publicKey: signer.publicKey }),
  }
  const params = {
    opKind: 'kokuin/vault-op/v1',
    methods: [method],
    authority: { authorize: async () => true },
    validateConsumerMetadata: async () => true,
    portsFor: () => {
      throw new Error('Unexpected ports')
    },
  }
  const op = await verifySignedRecord({
    record: source.key,
    opKind: params.opKind,
    methods: params.methods,
  })
  if (op === null) throw new Error('Invalid fixture')
  const definition = vaultRecordTypes(params).get('vault.key')
  if (definition === undefined) throw new Error('Missing definition')
  const reject = async (): Promise<never> => {
    throw new Error('Replacement resolver')
  }
  params.methods = [{ method: 'test', resolve: reject }]
  method.resolve = reject
  const store = {
    isTransaction: true,
    transaction: async () => {
      throw new Error('Unexpected transaction')
    },
    get: async () => null,
    list: async () => [],
    putCopy: async () => {},
    pruneCopy: async () => {},
  }
  await expect(
    definition.authorize({
      op,
      ctx: {
        record: source.key,
        stored: null,
        store,
        transportContext: undefined,
        resolveController: async () => null,
        verifyCapability: async () => false,
      },
    }),
  ).resolves.toBe(true)
})
