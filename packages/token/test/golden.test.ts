import { readFileSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { canonicalStringify } from '@sozai/codec'
import { expect, test } from 'vitest'

import { checkGolden, type GoldenCase } from '../../../scripts/golden.ts'
import { CODECS, getDID, getSignatureInfo, normalizeDID } from '../src/did.ts'
import { createIdentity, createSigningIdentity } from '../src/identity.ts'
import {
  assertDocWithinMaxSize,
  type DIDDoc,
  decodePeer4,
  encodePeer4,
  getPeer4ShortForm,
} from '../src/peer4.ts'
import { createUnsignedToken, isVerifiedToken, signToken, verifyToken } from '../src/token.ts'
import { stringifyToken } from '../src/utils.ts'

const file = fileURLToPath(new URL('./golden/tokens.json', import.meta.url))
const seeds = ['01'.repeat(32), '02'.repeat(32)]
const scalar = `${'00'.repeat(31)}01`

async function tokenCases(): Promise<Array<GoldenCase>> {
  const cases: Array<GoldenCase> = []
  const identities = seeds.map((seed) =>
    createSigningIdentity({ privateKey: Buffer.from(seed, 'hex') }),
  )
  for (const [index, signer] of identities.entries()) {
    const subject = identities[(index + 1) % identities.length]
    if (subject === undefined) throw new Error('Missing subject identity')
    const payload = {
      typ: 'note',
      sub: subject.id,
      nested: { z: [{ y: 2, a: 1 }], a: { z: false, a: 'first' } },
      iss: signer.id,
    }
    const header = { z: { z: 2, a: 1 }, a: 'first' }
    const signed = await signToken({
      signer,
      token: createUnsignedToken({ payload, header }),
    })
    const compact = stringifyToken(signed)
    const [headerPart, payloadPart, signature] = compact.split('.')
    if (headerPart === undefined || payloadPart === undefined || signature === undefined) {
      throw new Error('Missing compact token segment')
    }
    expect(Buffer.from(headerPart, 'base64url').toString('utf8')).toBe(
      '{"a":"first","alg":"EdDSA","typ":"JWT","z":{"a":1,"z":2}}',
    )
    expect(Buffer.from(payloadPart, 'base64url').toString('utf8')).toBe(
      `{"iss":"${signer.id}","nested":{"a":{"a":"first","z":false},"z":[{"a":1,"y":2}]},"sub":"${subject.id}","typ":"note"}`,
    )
    cases.push({
      name: `Ed25519 seed ${index + 1}: compact token`,
      input: {
        seed: seeds[index],
        subjectSeed: seeds[(index + 1) % seeds.length],
        header,
        payload,
      },
      expected: compact,
    })

    const verified = await verifyToken({ token: compact })
    expect(isVerifiedToken(verified)).toBe(true)
    expect(verified.payload).toEqual(payload)
    cases.push({
      name: `Ed25519 seed ${index + 1}: verify compact token`,
      input: { token: compact },
      expected: {
        verified: isVerifiedToken(verified),
        publicKey: Buffer.from(verified.verifiedPublicKey).toString('hex'),
        payload: verified.payload,
      },
    })

    // Sign the received JSON bytes directly, preserving whitespace and key order.
    const receivedHeader = `{ "typ": "JWT", "alg": "EdDSA" }`
    const receivedPayload = JSON.stringify(payload, null, 2)
    const receivedData = `${Buffer.from(receivedHeader).toString('base64url')}.${Buffer.from(receivedPayload).toString('base64url')}`
    const receivedSignature = ed25519.sign(
      Buffer.from(receivedData),
      Buffer.from(seeds[index], 'hex'),
    )
    const receivedToken = `${receivedData}.${Buffer.from(receivedSignature).toString('base64url')}`
    const receivedVerified = await verifyToken({ token: receivedToken })
    expect(isVerifiedToken(receivedVerified)).toBe(true)
    expect(receivedVerified.payload).toEqual(payload)
    cases.push({
      name: `Ed25519 seed ${index + 1}: verify signed non-canonical JSON`,
      input: { token: receivedToken },
      expected: {
        verified: isVerifiedToken(receivedVerified),
        publicKey: Buffer.from(receivedVerified.verifiedPublicKey).toString('hex'),
        payload: receivedVerified.payload,
      },
    })

    // Preserve the signature while changing the payload's signed bytes, but not its JSON value.
    const nonCanonicalPayload = JSON.stringify(payload)
    const tampered = `${headerPart}.${Buffer.from(nonCanonicalPayload).toString('base64url')}.${signature}`
    expect(JSON.parse(nonCanonicalPayload)).toEqual(
      JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8')),
    )
    expect(tampered).not.toBe(compact)
    let rejection: unknown
    try {
      await verifyToken({ token: tampered })
    } catch (error) {
      if (!(error instanceof Error)) throw error
      rejection = { error: error.name, message: error.message }
    }
    expect(rejection).toEqual({ error: 'Error', message: 'Invalid signature' })
    cases.push({
      name: `Ed25519 seed ${index + 1}: reject re-encoded payload`,
      input: { token: tampered },
      expected: rejection,
    })

    const [algorithm, publicKey] = getSignatureInfo(signer.id)
    expect(publicKey).toEqual(signer.publicKey)
    cases.push({
      name: `Ed25519 seed ${index + 1}: did:key`,
      input: { algorithm: 'EdDSA', seed: seeds[index] },
      expected: { did: signer.id, algorithm, publicKey: Buffer.from(publicKey).toString('hex') },
    })
  }

  const publicKey = p256.getPublicKey(Buffer.from(scalar, 'hex'), true)
  const did = getDID({ codec: CODECS.ES256, publicKey })
  const [algorithm, decodedPublicKey] = getSignatureInfo(did)
  expect(decodedPublicKey).toEqual(publicKey)
  cases.push({
    name: 'P-256: did:key',
    input: { algorithm: 'ES256', scalar },
    expected: { did, algorithm, publicKey: Buffer.from(publicKey).toString('hex') },
  })

  const signer = identities[0]
  if (signer === undefined) throw new Error('Missing document identity')
  const doc: DIDDoc = {
    authentication: ['#key-0'],
    verificationMethod: [
      { type: 'Multikey', publicKeyMultibase: signer.id.slice('did:key:'.length), id: '#key-0' },
    ],
    '@context': ['https://www.w3.org/ns/did/v1'],
    assertionMethod: ['#key-0'],
  }
  const { longForm, shortForm } = encodePeer4(doc)
  expect(decodePeer4({ longForm })).toEqual({ longForm, shortForm, doc })
  cases.push({
    name: 'did:peer:4: fixed document',
    input: { seed: seeds[0], doc },
    expected: { longForm, shortForm },
  })
  cases.push(...(await peer4Cases(doc)))
  return cases
}

type Rejection = { error: string; message: string }

async function rejectionOf(run: () => unknown): Promise<Rejection> {
  try {
    await run()
  } catch (error) {
    if (!(error instanceof Error)) throw error
    return { error: error.name, message: error.message }
  }
  throw new Error('Expected a rejection')
}

function signRaw(header: Record<string, unknown>, payload: Record<string, unknown>, seed: string) {
  const data = `${Buffer.from(canonicalStringify(header)).toString('base64url')}.${Buffer.from(canonicalStringify(payload)).toString('base64url')}`
  const signature = ed25519.sign(Buffer.from(data), Buffer.from(seed, 'hex'))
  return `${data}.${Buffer.from(signature).toString('base64url')}`
}

async function verifiedCase(
  name: string,
  input: { token: string; resolver?: Record<string, DIDDoc> },
): Promise<GoldenCase> {
  const docs = input.resolver
  const verified = await verifyToken({
    token: input.token,
    resolver: docs === undefined ? undefined : (did) => docs[did],
  })
  expect(isVerifiedToken(verified)).toBe(true)
  return {
    name,
    input,
    expected: {
      verified: isVerifiedToken(verified),
      publicKey: Buffer.from(verified.verifiedPublicKey).toString('hex'),
      header: verified.header,
      payload: verified.payload,
    },
  }
}

async function rejectedCase(
  name: string,
  input: { token: string; resolver?: Record<string, DIDDoc> },
): Promise<GoldenCase> {
  const docs = input.resolver
  const expected = await rejectionOf(() =>
    verifyToken({
      token: input.token,
      resolver: docs === undefined ? undefined : (did) => docs[did],
    }),
  )
  return { name, input, expected }
}

async function peer4Cases(otherDoc: DIDDoc): Promise<Array<GoldenCase>> {
  const cases: Array<GoldenCase> = []
  const sigSeed = '03'.repeat(32)
  const kemSeed = '04'.repeat(32)
  const identity = await createIdentity({
    didMethod: 'peer:4',
    keys: [
      { purpose: 'sig', alg: 'EdDSA', privateKey: Buffer.from(sigSeed, 'hex') },
      { purpose: 'kem', alg: 'X25519', privateKey: Buffer.from(kemSeed, 'hex') },
    ],
  })
  const { longForm, id: shortForm, doc } = identity
  expect(longForm).not.toBe(shortForm)

  // Decoding.
  const decoded = decodePeer4({ longForm })
  expect(decoded).toEqual({ longForm, shortForm, doc })
  cases.push({
    name: 'did:peer:4: long-form decode',
    input: { sigSeed, kemSeed, longForm },
    expected: { shortForm: decoded.shortForm, doc: decoded.doc },
  })
  cases.push({
    name: 'did:peer:4: short form of either form',
    input: { longForm, shortForm },
    expected: {
      fromLong: getPeer4ShortForm(longForm),
      fromShort: getPeer4ShortForm(shortForm),
      normalizedLong: normalizeDID(longForm),
      normalizedShort: normalizeDID(shortForm),
    },
  })
  cases.push({
    name: 'did:peer:4: short form is not decodable alone',
    input: { longForm: shortForm },
    expected: await rejectionOf(() => decodePeer4({ longForm: shortForm })),
  })
  const otherEncoded = encodePeer4(otherDoc).longForm.split(':').at(-1)
  const tampered = `${shortForm}:${otherEncoded}`
  cases.push({
    name: 'did:peer:4: reject long form whose doc does not match its hash',
    input: { longForm: tampered },
    expected: await rejectionOf(() => decodePeer4({ longForm: tampered })),
  })

  // Size limits on the embedded document.
  const docSize = Buffer.byteLength(canonicalStringify(doc))
  const tooSmall = await rejectionOf(() => decodePeer4({ longForm, maxDocSize: docSize - 1 }))
  expect(tooSmall.message).toBe(`did:peer:4 doc too large: ${docSize} > ${docSize - 1}`)
  cases.push({
    name: 'did:peer:4: reject doc over maxDocSize',
    input: { longForm, maxDocSize: docSize - 1 },
    expected: tooSmall,
  })
  const encodedTooLarge = await rejectionOf(() => decodePeer4({ longForm, maxDocSize: 16 }))
  expect(encodedTooLarge.message).toMatch(/^did:peer:4 encoded doc too large/)
  cases.push({
    name: 'did:peer:4: reject encoded doc over maxDocSize',
    input: { longForm, maxDocSize: 16 },
    expected: encodedTooLarge,
  })

  // Tokens from a did:peer:4 issuer.
  const payload = { typ: 'note', sub: 'did:example:subject' }
  const longSigned = await identity.signToken({ payload, embedLongForm: true })
  const longToken = stringifyToken(longSigned)
  cases.push(await verifiedCase('did:peer:4: verify long-form issuer token', { token: longToken }))

  const shortSigned = await identity.signToken({ payload, embedLongForm: false })
  const shortToken = stringifyToken(shortSigned)
  cases.push(
    await verifiedCase('did:peer:4: verify short-form issuer token through a resolver', {
      token: shortToken,
      resolver: { [shortForm]: doc },
    }),
  )
  cases.push(
    await rejectedCase('did:peer:4: reject short-form issuer without a resolver', {
      token: shortToken,
    }),
  )
  cases.push(
    await rejectedCase('did:peer:4: reject resolver doc with another hash', {
      token: shortToken,
      resolver: { [shortForm]: otherDoc },
    }),
  )

  const header = { typ: 'JWT', alg: 'EdDSA', kid: '#key-0' }
  const longPayload = { ...payload, iss: longForm }
  cases.push(
    await rejectedCase('did:peer:4: reject token signed by another key', {
      token: signRaw(header, longPayload, seeds[1] as string),
    }),
  )
  cases.push(
    await rejectedCase('did:peer:4: reject kid that is not an authentication method', {
      token: signRaw({ ...header, kid: '#key-1' }, longPayload, sigSeed),
    }),
  )
  cases.push(
    await rejectedCase('did:peer:4: reject unknown kid', {
      token: signRaw({ ...header, kid: '#key-9' }, longPayload, sigSeed),
    }),
  )

  // Resolver documents over the size and entry limits.
  const oversized: DIDDoc = { ...doc, service: 'x'.repeat(4096) }
  const oversizedRejection = await rejectionOf(() => assertDocWithinMaxSize(oversized))
  expect(oversizedRejection.message).toMatch(/^did:peer:4 resolver doc too large/)
  cases.push(
    await rejectedCase('did:peer:4: reject resolver doc over the size limit', {
      token: shortToken,
      resolver: { [shortForm]: oversized },
    }),
  )
  const crowded: DIDDoc = {
    ...doc,
    verificationMethod: Array.from({ length: 104 }, (_, index) => {
      return { id: `#k${index}`, type: 'Multikey', publicKeyMultibase: 'z' }
    }),
  }
  const crowdedRejection = await rejectionOf(() => assertDocWithinMaxSize(crowded))
  expect(crowdedRejection.message).toMatch(/too many verification methods: 104 > 103$/)
  cases.push(
    await rejectedCase('did:peer:4: reject resolver doc with too many verification methods', {
      token: shortToken,
      resolver: { [shortForm]: crowded },
    }),
  )

  // A payload without `iss` fails schema validation before any issuer is resolved.
  cases.push(
    await rejectedCase('Ed25519 seed 1: reject payload without iss', {
      token: signRaw({ typ: 'JWT', alg: 'EdDSA' }, { typ: 'note' }, seeds[0] as string),
    }),
  )
  return cases
}

test('golden: compact tokens and DID encodings', async () => {
  checkGolden(file, await tokenCases())
})

test.skipIf(process.env.UPDATE_GOLDEN === '1')(
  'golden: verification does not write the vector file',
  async () => {
    const before = { content: readFileSync(file, 'utf8'), mtime: statSync(file).mtimeMs }
    checkGolden(file, await tokenCases())
    expect(readFileSync(file, 'utf8')).toBe(before.content)
    expect(statSync(file).mtimeMs).toBe(before.mtime)
  },
)
