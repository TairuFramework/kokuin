import {
  createIdentity,
  normalizeDID,
  randomIdentity,
  type SigningIdentity,
  stringifyToken,
} from '@kokuin/token'
import { blake3 } from '@noble/hashes/blake3.js'
import { b64uFromUTF, canonicalStringify, fromB64U, fromUTF, toB64U, toUTF } from '@sozai/codec'
import { HLC } from '@sozai/hlc'
import { describe, expect, test } from 'vitest'

import {
  canonicalRecordClaim,
  isRecordClaim,
  MAX_RECORD_ID_LENGTH,
  type RecordClaim,
  RecordClaimError,
  rangeLeaf,
  recordClaimDigest,
  recordPayloadDigest,
  recordPayloadMatches,
  type SignedRecord,
  signRecordOp,
  verifyRecordOp,
  verifySignedRecord,
} from '../src/index.js'

const TEST_OP_KIND = 'test/record-op'

type TestIdentity = SigningIdentity

function liveClaim(identity: TestIdentity, payload: Uint8Array): RecordClaim {
  return {
    type: 'credential.entry',
    id: 'entry-1',
    owner: normalizeDID(identity.id),
    hlc: HLC.serialize({ wallTime: Date.now(), counter: 0, nodeID: identity.id }),
    payloadDigest: recordPayloadDigest(payload),
    deleted: false,
    meta: { keyID: 'key-1', keyVersion: 1 },
  }
}

async function signedRecord(
  identity: TestIdentity,
  claim: RecordClaim,
  payload: Uint8Array | null,
): Promise<SignedRecord> {
  const { opJWT, opHash } = await signRecordOp(identity, claim, TEST_OP_KIND)
  return {
    type: claim.type,
    id: claim.id,
    owner: claim.owner,
    hlc: claim.hlc,
    payload,
    opJWT,
    opHash,
  }
}

// A token the identity really signed, carrying whatever payload the test chooses — so a
// rejection can only come from the record checks, never from a broken signature.
async function signRaw(identity: TestIdentity, payload: Record<string, unknown>): Promise<string> {
  return stringifyToken(await identity.signToken(payload, { embedLongForm: true }))
}

describe('canonicalRecordClaim', () => {
  test('sorts object keys recursively and keeps array order', () => {
    const claim: RecordClaim = {
      type: 't',
      id: 'i',
      owner: 'did:key:o',
      hlc: 'h',
      payloadDigest: null,
      deleted: true,
      meta: { z: [3, 1, { b: 1, a: 2 }], a: 'x' },
    }
    expect(toUTF(canonicalRecordClaim(claim))).toBe(
      '{"deleted":true,"hlc":"h","id":"i","meta":{"a":"x","z":[3,1,{"a":2,"b":1}]},"owner":"did:key:o","payloadDigest":null,"type":"t"}',
    )
  })

  test('is independent of the key order the claim was written in', () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([1]))
    const reordered = Object.fromEntries(Object.entries(claim).reverse()) as RecordClaim
    expect(canonicalRecordClaim(reordered)).toEqual(canonicalRecordClaim(claim))
  })

  test('refuses a claim whose meta has no lossless JSON form', () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([1]))
    expect(() => canonicalRecordClaim({ ...claim, meta: { lost: undefined } })).toThrow(
      RecordClaimError,
    )
    expect(() => canonicalRecordClaim({ ...claim, meta: { n: Number.NaN } })).toThrow(
      RecordClaimError,
    )
    expect(() => canonicalRecordClaim({ ...claim, meta: { n: -0 } })).toThrow(RecordClaimError)
  })

  test('refuses a claim whose meta holds -0 inside an array or nested object', () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([1]))
    expect(() => canonicalRecordClaim({ ...claim, meta: { list: [1, -0] } })).toThrow(
      RecordClaimError,
    )
    expect(() => canonicalRecordClaim({ ...claim, meta: { a: { b: -0 } } })).toThrow(
      RecordClaimError,
    )
  })

  test('refuses a claim whose meta is cyclic with RecordClaimError', () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([1]))
    const meta: Record<string, unknown> = {}
    meta.self = meta
    expect(() => canonicalRecordClaim({ ...claim, meta })).toThrow(RecordClaimError)
  })

  test('refuses a claim whose meta has an accessor property', () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([1]))
    const meta = {}
    Object.defineProperty(meta, 'x', { get: () => 1, enumerable: true })
    expect(() => canonicalRecordClaim({ ...claim, meta })).toThrow(RecordClaimError)
  })

  test('isRecordClaim rejects a sparse array in meta', () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([1]))
    // biome-ignore lint/suspicious/noSparseArray: the hole is the case under test
    expect(isRecordClaim({ ...claim, meta: { list: [, 1] } })).toBe(false)
  })
})

describe('recordPayloadDigest', () => {
  test('hashes exact bytes, and a tombstone has no digest', () => {
    const encoder = new TextEncoder()
    expect(recordPayloadDigest(null)).toBeNull()
    expect(recordPayloadDigest(encoder.encode('{"a":1}'))).toBe(
      recordPayloadDigest(encoder.encode('{"a":1}')),
    )
    // Same JSON value, different bytes: the digest must not look through the encoding.
    expect(recordPayloadDigest(encoder.encode('{"a":1}'))).not.toBe(
      recordPayloadDigest(encoder.encode('{ "a": 1 }')),
    )
  })
})

describe('signRecordOp / verifyRecordOp', () => {
  test('signs canonical claim bytes and verifies the bound issuer', async () => {
    const identity = randomIdentity()
    const payload = new TextEncoder().encode('secret bytes')
    const claim: RecordClaim = {
      type: 'credential.entry',
      id: 'entry-1',
      owner: normalizeDID(identity.id),
      hlc: HLC.serialize({ wallTime: Date.now(), counter: 0, nodeID: identity.id }),
      payloadDigest: recordPayloadDigest(payload),
      deleted: false,
      meta: { keyID: 'key-1', keyVersion: 1 },
    }
    const signed = await signRecordOp(identity, claim, TEST_OP_KIND)
    expect(await verifyRecordOp(signed.opJWT, TEST_OP_KIND)).toEqual({
      issuer: normalizeDID(identity.id),
      claim,
      opHash: signed.opHash,
    })
    expect(await verifyRecordOp(`${signed.opJWT}x`, TEST_OP_KIND)).toBeNull()
  })

  test('one identity is called one at a time, in call order, and a failure frees the queue', async () => {
    const identity = randomIdentity()
    const order: Array<string> = []
    let active = false
    let failNext = true
    const signer: SigningIdentity = {
      ...identity,
      async signToken(payload, options) {
        if (active) throw new Error('Overlapping signer call')
        active = true
        try {
          order.push(String(payload.claim))
          await new Promise((resolve) => setTimeout(resolve, 1))
          if (failNext) {
            failNext = false
            throw new Error('Device refused')
          }
          return await identity.signToken(payload, options)
        } finally {
          active = false
        }
      },
    }
    const claims = [1, 2, 3, 4].map((byte) => liveClaim(identity, new Uint8Array([byte])))
    const results = await Promise.allSettled(
      claims.map((claim) => signRecordOp(signer, claim, TEST_OP_KIND)),
    )

    expect(results.map((result) => result.status)).toEqual([
      'rejected',
      'fulfilled',
      'fulfilled',
      'fulfilled',
    ])
    expect(order).toEqual(claims.map((claim) => toB64U(canonicalRecordClaim(claim))))
  })

  test('the signed token carries the canonical claim bytes under the domain marker', async () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([7]))
    const { opJWT } = await signRecordOp(identity, claim, TEST_OP_KIND)
    const body = JSON.parse(toUTF(fromB64U(opJWT.split('.')[1] as string)))
    expect(body.kind).toBe(TEST_OP_KIND)
    expect(fromB64U(body.claim)).toEqual(canonicalRecordClaim(claim))
  })

  test.each([
    ['expiry', { exp: Math.floor(Date.now() / 1000) + 3600 }, {}],
    ['not-before', { nbf: Math.floor(Date.now() / 1000) - 10 }, {}],
    ['extra payload', { extra: 'value' }, {}],
    ['extra header', {}, { extra: 'value' }],
  ])('rejects a signed record op with %s', async (_name, extraPayload, header) => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([7]))
    const opJWT = stringifyToken(
      await identity.signToken(
        { kind: TEST_OP_KIND, claim: toB64U(canonicalRecordClaim(claim)), ...extraPayload },
        { embedLongForm: true, header },
      ),
    )
    expect(await verifyRecordOp(opJWT, TEST_OP_KIND)).toBeNull()
  })

  test('signs and verifies a tombstone with a null digest', async () => {
    const identity = randomIdentity()
    const claim: RecordClaim = {
      ...liveClaim(identity, new Uint8Array([1])),
      payloadDigest: null,
      deleted: true,
      meta: {},
    }
    const signed = await signRecordOp(identity, claim, TEST_OP_KIND)
    expect(await verifyRecordOp(signed.opJWT, TEST_OP_KIND)).toEqual({
      issuer: normalizeDID(identity.id),
      claim,
      opHash: signed.opHash,
    })
  })

  test('opHash addresses the exact token and survives a serialization round trip', async () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([1, 2, 3]))
    const signed = await signRecordOp(identity, claim, TEST_OP_KIND)
    const replayed = JSON.parse(JSON.stringify(signed)) as typeof signed
    const verified = await verifyRecordOp(replayed.opJWT, TEST_OP_KIND)
    expect(verified?.opHash).toBe(signed.opHash)
    // Signing is deterministic and the token carries no issue time, so re-signing the same
    // claim is the same op — a replay, not a rival at the same position.
    const again = await signRecordOp(identity, claim, TEST_OP_KIND)
    expect(again).toEqual(signed)
    const changed = await signRecordOp(
      identity,
      {
        ...claim,
        meta: { keyID: 'key-1', keyVersion: 2 },
      },
      TEST_OP_KIND,
    )
    expect(changed.opHash).not.toBe(signed.opHash)
  })

  test('the issuer comes from the verified signature, not from the claim', async () => {
    const author = randomIdentity()
    const victim = randomIdentity()
    // The author signs a claim naming someone else as owner: verification must still
    // report the author as issuer, leaving the owner check to the record binding.
    const claim = { ...liveClaim(author, new Uint8Array([1])), owner: normalizeDID(victim.id) }
    const verified = await verifyRecordOp(
      (await signRecordOp(author, claim, TEST_OP_KIND)).opJWT,
      TEST_OP_KIND,
    )
    expect(verified?.issuer).toBe(normalizeDID(author.id))
    expect(verified?.claim.owner).toBe(normalizeDID(victim.id))
  })

  test('one issuer with two signing keys produces two distinct range holders', async () => {
    const identity = await createIdentity({
      didMethod: 'peer:4',
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'sig', alg: 'EdDSA' },
      ],
    })
    const claim = liveClaim(identity, new Uint8Array([1]))
    const encoded = toB64U(canonicalRecordClaim(claim))
    const copies = await Promise.all(
      ['#key-0', '#key-1'].map(async (kid) => {
        const opJWT = stringifyToken(
          await identity.signToken(
            { kind: TEST_OP_KIND, claim: encoded },
            { embedLongForm: true, kid },
          ),
        )
        return {
          type: claim.type,
          id: claim.id,
          owner: claim.owner,
          hlc: claim.hlc,
          payload: new Uint8Array([1]),
          opJWT,
          opHash: toB64U(blake3(fromUTF(`${opJWT.length}:${opJWT}`), { dkLen: 32 })),
        }
      }),
    )
    expect((await verifySignedRecord(copies[0] as SignedRecord, TEST_OP_KIND))?.issuer).toBe(
      claim.owner,
    )
    expect((await verifySignedRecord(copies[1] as SignedRecord, TEST_OP_KIND))?.issuer).toBe(
      claim.owner,
    )
    const base = {
      key: { type: claim.type, owner: claim.owner, id: claim.id },
      decisionHLC: claim.hlc,
      contentDigest: recordClaimDigest(claim),
    }
    const first = rangeLeaf({ ...base, copies: [copies[0] as SignedRecord] }, { kind: 'lww' })
    const second = rangeLeaf({ ...base, copies: [copies[1] as SignedRecord] }, { kind: 'lww' })
    const both = rangeLeaf({ ...base, copies }, { kind: 'lww' })
    expect(first?.opHash).not.toBe(second?.opHash)
    expect(both?.signers).toHaveLength(2)
  })

  test('refuses to sign a malformed claim', async () => {
    const identity = randomIdentity()
    const claim = liveClaim(identity, new Uint8Array([1]))
    await expect(
      signRecordOp(identity, { ...claim, payloadDigest: null }, TEST_OP_KIND),
    ).rejects.toThrow(RecordClaimError)
    await expect(signRecordOp(identity, { ...claim, deleted: true }, TEST_OP_KIND)).rejects.toThrow(
      RecordClaimError,
    )
  })

  test('an id is at most MAX_RECORD_ID_LENGTH UTF-16 units', async () => {
    const identity = randomIdentity()
    const atBound = { ...liveClaim(identity, new Uint8Array([1])), id: 'x'.repeat(1024) }
    const past = { ...atBound, id: 'x'.repeat(1025) }
    expect(MAX_RECORD_ID_LENGTH).toBe(1024)
    expect(isRecordClaim(atBound)).toBe(true)
    expect(isRecordClaim(past)).toBe(false)
    await expect(signRecordOp(identity, past, TEST_OP_KIND)).rejects.toThrow(RecordClaimError)
    const token = await signRaw(identity, {
      kind: TEST_OP_KIND,
      claim: toB64U(fromUTF(canonicalStringify(past))),
    })
    expect(await verifyRecordOp(token, TEST_OP_KIND)).toBeNull()
  })

  test('an owner has one spelling: a long-form peer:4 owner is refused', async () => {
    const peer4 = await createIdentity({
      didMethod: 'peer:4',
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
    })
    expect(peer4.longForm).not.toBe(peer4.id)
    expect(normalizeDID(peer4.longForm)).toBe(peer4.id)
    const short = liveClaim(peer4, new Uint8Array([1]))
    const long = { ...short, owner: peer4.longForm }
    expect(isRecordClaim(short)).toBe(true)
    expect(isRecordClaim(long)).toBe(false)
    await expect(signRecordOp(peer4, long, TEST_OP_KIND)).rejects.toThrow(RecordClaimError)
    // Hand-signed canonical bytes naming the long form do not verify either.
    const token = await signRaw(peer4, {
      kind: TEST_OP_KIND,
      claim: toB64U(fromUTF(canonicalStringify(long))),
    })
    expect(await verifyRecordOp(token, TEST_OP_KIND)).toBeNull()
    expect(
      (await verifyRecordOp((await signRecordOp(peer4, short, TEST_OP_KIND)).opJWT, TEST_OP_KIND))
        ?.claim,
    ).toEqual(short)
  })

  describe('rejects', () => {
    test('an unsigned token', async () => {
      const identity = randomIdentity()
      const claim = liveClaim(identity, new Uint8Array([1]))
      const header = b64uFromUTF(JSON.stringify({ typ: 'JWT', alg: 'none' }))
      const body = b64uFromUTF(
        JSON.stringify({
          iss: identity.id,
          kind: TEST_OP_KIND,
          claim: toB64U(canonicalRecordClaim(claim)),
        }),
      )
      expect(await verifyRecordOp(`${header}.${body}.`, TEST_OP_KIND)).toBeNull()
    })

    test('garbage', async () => {
      expect(await verifyRecordOp('', TEST_OP_KIND)).toBeNull()
      expect(await verifyRecordOp('not.a.token', TEST_OP_KIND)).toBeNull()
    })

    test('a signature over a different body', async () => {
      const identity = randomIdentity()
      const claim = liveClaim(identity, new Uint8Array([1]))
      const [header, , signature] = (await signRecordOp(identity, claim, TEST_OP_KIND)).opJWT.split(
        '.',
      )
      const forged = b64uFromUTF(
        JSON.stringify({
          iss: identity.id,
          kind: TEST_OP_KIND,
          claim: toB64U(canonicalRecordClaim({ ...claim, id: 'entry-2' })),
        }),
      )
      expect(await verifyRecordOp(`${header}.${forged}.${signature}`, TEST_OP_KIND)).toBeNull()
    })

    test('a wrong domain marker', async () => {
      const identity = randomIdentity()
      const claim = toB64U(canonicalRecordClaim(liveClaim(identity, new Uint8Array([1]))))
      expect(
        await verifyRecordOp(await signRaw(identity, { kind: 'test/other', claim }), TEST_OP_KIND),
      ).toBeNull()
      expect(await verifyRecordOp(await signRaw(identity, { claim }), TEST_OP_KIND)).toBeNull()
    })

    test('a claim spelled outside its canonical bytes', async () => {
      const identity = randomIdentity()
      const claim = liveClaim(identity, new Uint8Array([1]))
      const spaced = new TextEncoder().encode(JSON.stringify(claim, null, 1))
      const token = await signRaw(identity, { kind: TEST_OP_KIND, claim: toB64U(spaced) })
      expect(await verifyRecordOp(token, TEST_OP_KIND)).toBeNull()
      // The same claim in canonical bytes is accepted, so the rejection is the spelling.
      const canonical = await signRaw(identity, {
        kind: TEST_OP_KIND,
        claim: toB64U(canonicalRecordClaim(claim)),
      })
      expect((await verifyRecordOp(canonical, TEST_OP_KIND))?.claim).toEqual(claim)
    })

    test.each([
      [
        'a duplicate key',
        (text: string) => text.replace('"id":"entry-1"', '"id":"entry-1","id":"entry-1"'),
      ],
      [
        'an escaped plain character',
        (text: string) => text.replace('"entry-1"', '"\\u0065ntry-1"'),
      ],
      [
        'a number spelled 1.0',
        (text: string) => text.replace('"keyVersion":1', '"keyVersion":1.0'),
      ],
    ])('a claim spelled non-canonically: %s', async (_label, respell) => {
      const identity = randomIdentity()
      const claim = liveClaim(identity, new Uint8Array([1]))
      const canonical = toUTF(canonicalRecordClaim(claim))
      const respelled = respell(canonical)
      // Only the spelling changed: the text differs but parses to the same claim.
      expect(respelled).not.toBe(canonical)
      expect(JSON.parse(respelled)).toEqual(claim)
      const token = await signRaw(identity, {
        kind: TEST_OP_KIND,
        claim: toB64U(new TextEncoder().encode(respelled)),
      })
      expect(await verifyRecordOp(token, TEST_OP_KIND)).toBeNull()
    })

    test.each([
      ['signature', 2],
      ['payload', 1],
    ])('a token re-spelled with padding on its %s segment', async (_segment, index) => {
      const identity = randomIdentity()
      // Pick an id whose segment length leaves room for padding, so the re-spelled token
      // decodes to the same bytes rather than failing to decode.
      for (let length = 1; length <= 4; length++) {
        const claim = { ...liveClaim(identity, new Uint8Array([1])), id: 'e'.repeat(length) }
        const { opJWT } = await signRecordOp(identity, claim, TEST_OP_KIND)
        const segments = opJWT.split('.')
        const segment = segments[index] as string
        const padding = '='.repeat((4 - (segment.length % 4)) % 4)
        if (padding === '') {
          continue
        }
        expect(fromB64U(`${segment}${padding}`)).toEqual(fromB64U(segment))
        segments[index] = `${segment}${padding}`
        expect(await verifyRecordOp(segments.join('.'), TEST_OP_KIND)).toBeNull()
        return
      }
      throw new Error('no claim length left room for padding on this segment')
    })

    test('a token with padding appended to its header segment', async () => {
      const identity = randomIdentity()
      const { opJWT } = await signRecordOp(
        identity,
        liveClaim(identity, new Uint8Array([1])),
        TEST_OP_KIND,
      )
      const [header, payload, signature] = opJWT.split('.') as [string, string, string]
      // The header's length is a multiple of four, so no padded spelling of it decodes; the
      // re-spelled token must still be refused rather than reaching the claim.
      expect(header.length % 4).toBe(0)
      expect(await verifyRecordOp(`${header}==.${payload}.${signature}`, TEST_OP_KIND)).toBeNull()
      expect(await verifyRecordOp(`${header}=.${payload}.${signature}`, TEST_OP_KIND)).toBeNull()
    })

    test('the signature segment followed by padding', async () => {
      const identity = randomIdentity()
      const { opJWT } = await signRecordOp(
        identity,
        liveClaim(identity, new Uint8Array([1])),
        TEST_OP_KIND,
      )
      expect(await verifyRecordOp(`${opJWT}==`, TEST_OP_KIND)).toBeNull()
    })

    test('a claim carried as JSON rather than bytes', async () => {
      const identity = randomIdentity()
      const claim = liveClaim(identity, new Uint8Array([1]))
      expect(
        await verifyRecordOp(await signRaw(identity, { kind: TEST_OP_KIND, claim }), TEST_OP_KIND),
      ).toBeNull()
    })

    test.each([
      ['a missing field', (claim: Record<string, unknown>) => ({ ...claim, meta: undefined })],
      ['an extra field', (claim: Record<string, unknown>) => ({ ...claim, extra: 1 })],
      ['a non-string id', (claim: Record<string, unknown>) => ({ ...claim, id: 1 })],
      ['an array meta', (claim: Record<string, unknown>) => ({ ...claim, meta: [] })],
      [
        'a live op without a digest',
        (claim: Record<string, unknown>) => ({ ...claim, payloadDigest: null }),
      ],
      [
        'a tombstone with a digest',
        (claim: Record<string, unknown>) => ({ ...claim, deleted: true }),
      ],
    ])('a malformed claim: %s', async (_label, mutate) => {
      const identity = randomIdentity()
      const claim = mutate(liveClaim(identity, new Uint8Array([1])))
      const bytes = new TextEncoder().encode(canonicalJSONForTest(claim))
      const token = await signRaw(identity, { kind: TEST_OP_KIND, claim: toB64U(bytes) })
      expect(await verifyRecordOp(token, TEST_OP_KIND)).toBeNull()
    })
  })
})

describe('verifySignedRecord / recordPayloadMatches', () => {
  test('accepts a record its op speaks for', async () => {
    const identity = randomIdentity()
    const payload = new Uint8Array([9, 9])
    const claim = liveClaim(identity, payload)
    const record = await signedRecord(identity, claim, payload)
    const verified = await verifySignedRecord(record, TEST_OP_KIND)
    expect(verified).toEqual({ issuer: normalizeDID(identity.id), claim, opHash: record.opHash })
    expect(recordPayloadMatches(record, claim)).toBe(true)
  })

  test('rejects an owner the op did not sign', async () => {
    const identity = randomIdentity()
    const payload = new Uint8Array([1])
    const record = await signedRecord(identity, liveClaim(identity, payload), payload)
    const takeover = { ...record, owner: normalizeDID(randomIdentity().id) }
    expect(await verifySignedRecord(takeover, TEST_OP_KIND)).toBeNull()
  })

  test.each([
    ['type', { type: 'credential.key' }],
    ['id', { id: 'entry-2' }],
    ['hlc', { hlc: HLC.serialize({ wallTime: 1, counter: 0, nodeID: 'n' }) }],
    ['opHash', { opHash: 'forged' }],
  ])('rejects a record whose %s differs from its op', async (_field, change) => {
    const identity = randomIdentity()
    const payload = new Uint8Array([1])
    const record = await signedRecord(identity, liveClaim(identity, payload), payload)
    expect(await verifySignedRecord({ ...record, ...change }, TEST_OP_KIND)).toBeNull()
  })

  test('rejects a record whose op token was altered', async () => {
    const identity = randomIdentity()
    const payload = new Uint8Array([1])
    const record = await signedRecord(identity, liveClaim(identity, payload), payload)
    expect(
      await verifySignedRecord({ ...record, opJWT: `${record.opJWT}x` }, TEST_OP_KIND),
    ).toBeNull()
  })

  test('a payload digest mismatch fails the payload check', async () => {
    const identity = randomIdentity()
    const payload = new Uint8Array([1])
    const claim = liveClaim(identity, payload)
    const record = await signedRecord(identity, claim, payload)
    expect(recordPayloadMatches({ ...record, payload: new Uint8Array([2]) }, claim)).toBe(false)
    expect(recordPayloadMatches({ ...record, payload: null }, claim)).toBe(false)
  })

  test('a tombstone matches only an absent payload', async () => {
    const identity = randomIdentity()
    const claim: RecordClaim = {
      ...liveClaim(identity, new Uint8Array([1])),
      payloadDigest: null,
      deleted: true,
    }
    const record = await signedRecord(identity, claim, null)
    expect(await verifySignedRecord(record, TEST_OP_KIND)).not.toBeNull()
    expect(recordPayloadMatches(record, claim)).toBe(true)
    expect(recordPayloadMatches({ ...record, payload: new Uint8Array() }, claim)).toBe(false)
  })
})

// Sorted-key JSON without the record module's shape checks, so a test can sign a malformed
// claim in otherwise canonical bytes.
function canonicalJSONForTest(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJSONForTest).join(',')}]`
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJSONForTest(item)}`).join(',')}}`
}

test('record ops verify only in their signing replay domain', async () => {
  const identity = randomIdentity()
  const claim = liveClaim(identity, new Uint8Array([1]))
  const signed = await signRecordOp(identity, claim, 'a/op')
  expect(await verifyRecordOp(signed.opJWT, 'a/op')).not.toBeNull()
  expect(await verifyRecordOp(signed.opJWT, 'b/op')).toBeNull()
})
