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
    id: vaultRevocationRecordID(source.keyID, owner.id),
    owner: owner.id,
    hlc: stamp(200),
    payload: encodeVaultRecordPayload('vault.revocation', {}),
    meta: { keyID: source.keyID, revokedDID: owner.id, consumer: {} },
  })
  const records = [
    source.key,
    source.branch,
    await dependent(owner, source, 'vault.wrapping'),
    await dependent(owner, source, 'vault.entry'),
    revoke,
  ] as const
  for (const record of records) {
    const op = await verified(record)
    const decoded = decodeVaultRecord(record, op.claim.meta)
    expect(decoded.meta).toEqual(op.claim.meta)
    expect(encodeVaultRecordPayload(decoded.type, decoded.payload)).toEqual(record.payload)
  }
  const entry = decodeVaultRecord(records[3], (await verified(records[3])).claim.meta)
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
  const entry = await dependent(owner, source, 'vault.entry')
  const wrapping = await dependent(owner, source, 'vault.wrapping')
  const revocation = await signed(owner, {
    type: 'vault.revocation',
    id: vaultRevocationRecordID(source.keyID, owner.id),
    owner: owner.id,
    hlc: stamp(200),
    payload: encodeVaultRecordPayload('vault.revocation', {}),
    meta: { keyID: source.keyID, revokedDID: owner.id, consumer: {} },
  })
  for (const record of [source.key, source.branch, wrapping, entry, revocation]) {
    const broken = await resign(owner, record, { payload: fromUTF('{"unexpected":1}') })
    expect((await peer.apply([broken])).rejected.map((r) => r.reason)).toEqual(['unauthorized'])
    expect(() => decodeVaultRecord(broken, {})).toThrow(VaultRecordPayloadError)
    const op = await verified(record)
    expect(() => decodeVaultRecord({ ...record, payload: null }, op.claim.meta)).toThrow(
      VaultRecordPayloadError,
    )
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
    const broken = await resign(owner, entry, { payload: fromUTF(text) })
    expect(() => decodeVaultRecord(broken, op.claim.meta)).toThrow(VaultRecordPayloadError)
    expect((await peer.apply([broken])).rejected.map((r) => r.reason)).toEqual(['unauthorized'])
  }
})

test('branch codec refuses missing suite and wrong payload address; revocation binds its recipient', async () => {
  const owner = randomIdentity()
  const source = await chain(owner)
  const op = await verified(source.branch)
  const decoded = decodeVaultRecord(source.branch, op.claim.meta)
  if (decoded.type !== 'vault.key-branch') throw new Error('Fixture type')
  const { suite: _suite, ...payload } = decoded.payload
  const bytes = fromUTF(canonicalStringify(payload))
  expect(() =>
    decodeVaultRecord(
      { ...source.branch, id: recordPayloadDigest(bytes) as string, payload: bytes },
      op.claim.meta,
    ),
  ).toThrow(VaultRecordPayloadError)
  expect(() =>
    decodeVaultRecord({ ...source.branch, id: toB64U(new Uint8Array(32)) }, op.claim.meta),
  ).toThrow(VaultRecordPayloadError)
  const peer = memoryStore()
  await peer.apply([source.key])
  const revoke = await signed(owner, {
    type: 'vault.revocation',
    id: 'wrong-address',
    owner: owner.id,
    hlc: stamp(200),
    payload: encodeVaultRecordPayload('vault.revocation', {}),
    meta: { keyID: source.keyID, revokedDID: owner.id, consumer: {} },
  })
  expect((await peer.apply([revoke])).rejected.map((r) => r.reason)).toEqual(['unauthorized'])
})
