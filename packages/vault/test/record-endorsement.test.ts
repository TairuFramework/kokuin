import { recordDecisionDigest } from '@kokuin/records'
import { randomIdentity } from '@kokuin/token'
import { fromB64U, fromUTF, toB64U } from '@sozai/codec'
import { expect, test } from 'vitest'

import type { CredentialAuthority } from '../src/index.js'
import { chain, memoryStore, OP_KIND, resign } from './record-fixture.js'

// Models the consumer's historic membership contract, including pinned signature verification.
test('removed own copies refuse new receipt and effective members re-endorse identical content', async () => {
  const origin = randomIdentity()
  const survivor = randomIdentity()
  const owner = randomIdentity()
  const incarnations = {
    [origin.id]: { add: toB64U(new Uint8Array(32).fill(1)), g: 0 },
    [survivor.id]: { add: toB64U(new Uint8Array(32).fill(2)), g: 0 },
  }
  let removed = false
  const authority: CredentialAuthority = {
    async authorize(request) {
      const consumer = request.op.claim.meta.consumer as { incarnations: typeof incarnations }
      const member = consumer.incarnations[request.issuer]
      const historic =
        member && member.add === incarnations[request.issuer]?.add && member.g === 0
          ? {
              key: request.issuer === origin.id ? origin.publicKey : survivor.publicKey,
              lease: null,
              removed: request.issuer === origin.id && removed,
            }
          : null
      if (historic === null || historic.removed) return false
      const [header, body, signature] = request.record.opJWT.split('.')
      if (!header || !body || !signature) return false
      const publicKey = await crypto.subtle.importKey(
        'raw',
        Uint8Array.from(historic.key),
        'Ed25519',
        false,
        ['verify'],
      )
      return await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        Uint8Array.from(fromB64U(signature)),
        Uint8Array.from(fromUTF(`${header}.${body}`)),
      )
    },
  }
  const sender = memoryStore()
  const receiver = memoryStore()
  const source = await chain(origin, { owner: owner.id, consumer: { incarnations } })
  expect((await sender.apply([source.key], { authority })).applied).toBe(1)
  removed = true
  expect((await receiver.apply([source.key], { authority })).rejected.map((r) => r.reason)).toEqual(
    ['unauthorized'],
  )
  expect(await receiver.store.get(source.key)).toBeNull()
  const copy = await resign(survivor, source.key)
  expect(copy.opHash).not.toBe(source.key.opHash)
  expect(copy.payload).toEqual(source.key.payload)
  expect(await recordDecisionDigest(copy, OP_KIND)).toBe(
    await recordDecisionDigest(source.key, OP_KIND),
  )
  expect((await sender.apply([copy], { authority })).applied).toBe(1)
  const copies = (await sender.store.list(['vault.key'])).flatMap((d) => d.copies)
  expect(copies.map((r) => r.opHash)).toEqual([copy.opHash])
  expect((await receiver.apply(structuredClone(copies), { authority })).rejected).toEqual([])
  expect((await receiver.store.get(copy))?.copies.map((r) => r.opHash)).toEqual([copy.opHash])
})
