import { recordPayloadDigest } from '@kokuin/records'
import { randomIdentity } from '@kokuin/token'
import { canonicalStringify, fromUTF, toB64U } from '@sozai/codec'
import { expect, test } from 'vitest'

import {
  decodeVaultRecord,
  encodeVaultRecordPayload,
  VaultRecordPayloadError,
  vaultRevocationRecordID,
} from '../src/index.js'
import { chain, dependent, memoryStore, resign, signed, stamp, verified } from './record-fixture.js'

test('all five pure codecs round-trip exact canonical bytes and signed metadata', async () => {
  const owner = randomIdentity()
  const source = await chain(owner)
  const revoke = await signed(owner, {
    type: 'vault.revocation',
    id: vaultRevocationRecordID({ keyID: source.keyID, recipientDID: owner.id }),
    owner: owner.id,
    hlc: stamp(200),
    payload: encodeVaultRecordPayload({ type: 'vault.revocation', payload: {} }),
    meta: { keyID: source.keyID, revokedDID: owner.id, consumer: {} },
  })
  const records = [
    source.key,
    source.branch,
    await dependent({ signer: owner, source, type: 'vault.wrapping' }),
    await dependent({ signer: owner, source, type: 'vault.entry' }),
    revoke,
  ] as const
  for (const record of records) {
    const op = await verified(record)
    const decoded = await decodeVaultRecord({ record, recordMeta: op.claim.meta })
    expect(decoded.meta).toEqual(op.claim.meta)
    expect(encodeVaultRecordPayload({ type: decoded.type, payload: decoded.payload })).toEqual(
      record.payload,
    )
  }
  const entry = await decodeVaultRecord({
    record: records[3],
    recordMeta: (await verified(records[3])).claim.meta,
  })
  if (entry.type !== 'vault.entry') throw new Error('Fixture type')
  expect(entry.payload.ciphertext).toEqual(new Uint8Array([128, 255, 0]))
  expect(entry.meta).toMatchObject({
    kind: 'blob',
    label: 'State',
    attributes: { format: 'binary' },
  })
})

test('malformed canonical wire shapes refuse without throwing from apply', async () => {
  const owner = randomIdentity()
  const source = await chain(owner)
  const peer = memoryStore()
  await peer.apply([source.key, source.branch])
  const entry = await dependent({ signer: owner, source, type: 'vault.entry' })
  const wrapping = await dependent({ signer: owner, source, type: 'vault.wrapping' })
  const revocation = await signed(owner, {
    type: 'vault.revocation',
    id: vaultRevocationRecordID({ keyID: source.keyID, recipientDID: owner.id }),
    owner: owner.id,
    hlc: stamp(200),
    payload: encodeVaultRecordPayload({ type: 'vault.revocation', payload: {} }),
    meta: { keyID: source.keyID, revokedDID: owner.id, consumer: {} },
  })
  for (const record of [source.key, source.branch, wrapping, entry, revocation]) {
    const broken = await resign({
      signer: owner,
      record,
      changes: { payload: fromUTF('{"unexpected":1}') },
    })
    expect((await peer.apply([broken])).rejected.map((r) => r.reason)).toEqual(['unauthorized'])
    await expect(
      async () => await decodeVaultRecord({ record: broken, recordMeta: {} }),
    ).rejects.toThrow(VaultRecordPayloadError)
    const op = await verified(record)
    await expect(
      async () =>
        await decodeVaultRecord({
          record: { ...record, payload: null },
          recordMeta: op.claim.meta,
        }),
    ).rejects.toThrow(VaultRecordPayloadError)
  }
  const op = await verified(entry)
  for (const text of [
    '{"iv":"","ciphertext":""}',
    '{"ciphertext":"AA==","iv":"AA"}',
    '{"ciphertext":"AA","iv":7}',
    '{"ciphertext":"AA","extra":1,"iv":"AA"}',
    '[]',
    'not-json',
  ]) {
    const broken = await resign({
      signer: owner,
      record: entry,
      changes: { payload: fromUTF(text) },
    })
    await expect(
      async () => await decodeVaultRecord({ record: broken, recordMeta: op.claim.meta }),
    ).rejects.toThrow(VaultRecordPayloadError)
    expect((await peer.apply([broken])).rejected.map((r) => r.reason)).toEqual(['unauthorized'])
  }
})

test('branch codec refuses missing suite and wrong payload address; revocation binds its recipient', async () => {
  const owner = randomIdentity()
  const source = await chain(owner)
  const op = await verified(source.branch)
  const decoded = await decodeVaultRecord({ record: source.branch, recordMeta: op.claim.meta })
  if (decoded.type !== 'vault.key-branch') throw new Error('Fixture type')
  const { suite: _suite, ...payload } = decoded.payload
  const bytes = fromUTF(canonicalStringify(payload))
  await expect(async () => {
    return await decodeVaultRecord({
      record: {
        ...source.branch,
        id: (await recordPayloadDigest({ payload: bytes })) as string,
        payload: bytes,
      },
      recordMeta: op.claim.meta,
    })
  }).rejects.toThrow(VaultRecordPayloadError)
  await expect(async () => {
    return await decodeVaultRecord({
      record: { ...source.branch, id: toB64U(new Uint8Array(32)) },
      recordMeta: op.claim.meta,
    })
  }).rejects.toThrow(VaultRecordPayloadError)
  const peer = memoryStore()
  await peer.apply([source.key])
  const revoke = await signed(owner, {
    type: 'vault.revocation',
    id: 'wrong-address',
    owner: owner.id,
    hlc: stamp(200),
    payload: encodeVaultRecordPayload({ type: 'vault.revocation', payload: {} }),
    meta: { keyID: source.keyID, revokedDID: owner.id, consumer: {} },
  })
  expect((await peer.apply([revoke])).rejected.map((r) => r.reason)).toEqual(['unauthorized'])
})
