import { readFileSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { expect, test } from 'vitest'

import { checkGolden, type GoldenCase } from '../../../scripts/golden.ts'
import { CODECS, getDID, getSignatureInfo } from '../src/did.ts'
import { createSigningIdentity } from '../src/identity.ts'
import { type DIDDoc, decodePeer4, encodePeer4 } from '../src/peer4.ts'
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
