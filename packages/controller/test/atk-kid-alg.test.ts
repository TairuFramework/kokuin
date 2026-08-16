import { type MethodRegistry, verifyToken } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  type SignedEvent,
} from '../src/events.js'
import { encodeKey } from '../src/keys.js'
import { createControllerResolver } from '../src/resolver.js'

// ATTACK on `kid` selection, the algorithm/typ header and Ed25519 malleability.
// Every row is RE-SIGNED with the real key, so a rejection can only be the guard under test —
// never a signature that broke because the header was edited after signing.

const b64u = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url')
const b64uBytes = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url')

function signRaw(
  privateKey: Uint8Array,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const data = `${b64u(header)}.${b64u(payload)}`
  return `${data}.${b64uBytes(ed25519.sign(new TextEncoder().encode(data), privateKey))}`
}

const seed = new Uint8Array(32).fill(9)
const otherSeed = new Uint8Array(32).fill(19)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const otherInception = createInception(otherSeed, 0)
const otherDID = didFromInception(otherInception.event)

const k0 = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
const k1 = deriveKeyPair(seed, authorityPath(0, 0, 1), 'EdDSA')
const o0 = deriveKeyPair(otherSeed, authorityPath(0, 0, 0), 'EdDSA')

const rotated = createRotate({ seed, profile: 0, did, prior: inception.event })
const reset = createReset(seed, 0, 1)

function registryFor(log: Array<SignedEvent>, otherLog: Array<SignedEvent> = [otherInception]) {
  const methods: MethodRegistry = [
    createControllerResolver({
      loadLog: async (asked) => {
        if (asked === did) return log
        if (asked === otherDID) return otherLog
        return undefined
      },
    }),
  ]
  return methods
}

const payload = { iss: did, sub: did, aud: 'did:key:zSomeone', act: 'write', res: 'doc/1' }

async function attempt(
  log: Array<SignedEvent>,
  header: Record<string, unknown>,
  privateKey = k0.privateKey,
): Promise<string> {
  try {
    await verifyToken(signRaw(privateKey, header, payload), { methods: registryFor(log) })
    return 'ACCEPTED'
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
}

describe('ATTACK: kid selection through the real state resolver', () => {
  test('one mutation of the header kid at a time', async () => {
    const key0 = encodeKey(k0.publicKey, 'EdDSA')
    const rows: Array<[string, Record<string, unknown>]> = [
      [
        'CONTROL: the key that signed, in fragment form',
        { typ: 'JWT', alg: 'EdDSA', kid: `#${key0}` },
      ],
      ['no kid at all', { typ: 'JWT', alg: 'EdDSA' }],
      ['empty-string kid', { typ: 'JWT', alg: 'EdDSA', kid: '' }],
      ['a lone hash', { typ: 'JWT', alg: 'EdDSA', kid: '#' }],
      ['bare key, no fragment marker', { typ: 'JWT', alg: 'EdDSA', kid: key0 }],
      ['leading space', { typ: 'JWT', alg: 'EdDSA', kid: ` #${key0}` }],
      ['trailing NUL', { typ: 'JWT', alg: 'EdDSA', kid: `#${key0}\0` }],
      ['case-flipped key', { typ: 'JWT', alg: 'EdDSA', kid: `#${key0.toUpperCase()}` }],
      [
        'the pre-committed next key, not yet published',
        {
          typ: 'JWT',
          alg: 'EdDSA',
          kid: `#${encodeKey(k1.publicKey, 'EdDSA')}`,
        },
      ],
      [
        'a key from ANOTHER DID’s set',
        {
          typ: 'JWT',
          alg: 'EdDSA',
          kid: `#${encodeKey(o0.publicKey, 'EdDSA')}`,
        },
      ],
      [
        'the profile’s own agreement key',
        {
          typ: 'JWT',
          alg: 'EdDSA',
          kid: `#${inception.event.ka[0]}`,
        },
      ],
      ['a did:peer:4-style fragment', { typ: 'JWT', alg: 'EdDSA', kid: '#key-0' }],
    ]
    const results: Array<[string, string]> = []
    for (const [name, header] of rows) {
      results.push([name, await attempt([inception], header)])
    }
    expect(results[0][1], 'control').toBe('ACCEPTED')
    // Row 1 ("no kid at all") is documented: an absent kid resolves the head's first key, which
    // here is the key that signed. Every other row must be refused.
    expect(results[1][1], 'absent kid, documented default').toBe('ACCEPTED')
    for (const [name, outcome] of results.slice(2)) {
      expect(outcome, name).not.toBe('ACCEPTED')
    }
  })

  test('a key from an earlier position, and from a superseded generation', async () => {
    const key0 = encodeKey(k0.publicKey, 'EdDSA')
    const key1 = encodeKey(k1.publicKey, 'EdDSA')
    const rotatedLog = [inception, rotated]
    const resetLog = [inception, reset]

    const results = {
      'rotated log, head key': await attempt(
        rotatedLog,
        { typ: 'JWT', alg: 'EdDSA', kid: `#${key1}` },
        k1.privateKey,
      ),
      'rotated log, superseded-but-same-generation key': await attempt(rotatedLog, {
        typ: 'JWT',
        alg: 'EdDSA',
        kid: `#${key0}`,
      }),
      'rotated log, old key with NO kid': await attempt(rotatedLog, { typ: 'JWT', alg: 'EdDSA' }),
      'reset log, key from the previous generation': await attempt(resetLog, {
        typ: 'JWT',
        alg: 'EdDSA',
        kid: `#${key0}`,
      }),
    }
    expect(results['rotated log, head key']).toBe('ACCEPTED')
    expect(results['reset log, key from the previous generation']).not.toBe('ACCEPTED')
  })
})

describe('ATTACK: algorithm, typ and signature layer', () => {
  test('header mutations, each re-signed with the real key', async () => {
    const key0 = encodeKey(k0.publicKey, 'EdDSA')
    const results = {
      'CONTROL: untouched': await attempt([inception], {
        typ: 'JWT',
        alg: 'EdDSA',
        kid: `#${key0}`,
      }),
      'alg none (signature present)': await attempt([inception], {
        typ: 'JWT',
        alg: 'none',
        kid: `#${key0}`,
      }),
      'alg ES256, EdDSA signature': await attempt([inception], {
        typ: 'JWT',
        alg: 'ES256',
        kid: `#${key0}`,
      }),
      'alg EdDSA lowercased': await attempt([inception], {
        typ: 'JWT',
        alg: 'eddsa',
        kid: `#${key0}`,
      }),
      'typ JWS': await attempt([inception], { typ: 'JWS', alg: 'EdDSA', kid: `#${key0}` }),
      'typ absent': await attempt([inception], { alg: 'EdDSA', kid: `#${key0}` }),
      'header iss claiming another DID': await attempt([inception], {
        typ: 'JWT',
        alg: 'EdDSA',
        kid: `#${key0}`,
        iss: otherDID,
      }),
      'smuggled header act/res': await attempt([inception], {
        typ: 'JWT',
        alg: 'EdDSA',
        kid: `#${key0}`,
        act: 'revoke',
        res: '*',
      }),
    }
    expect(results['CONTROL: untouched']).toBe('ACCEPTED')
    expect(results['alg none (signature present)']).not.toBe('ACCEPTED')
    expect(results['typ JWS']).not.toBe('ACCEPTED')
  })

  test('a signer with the WRONG key, and Ed25519 S-malleability', async () => {
    const key0 = encodeKey(k0.publicKey, 'EdDSA')
    const header = { typ: 'JWT', alg: 'EdDSA', kid: `#${key0}` }

    // The wrong key entirely: the baseline that must never pass.
    const wrongKey = await attempt([inception], header, o0.privateKey)

    // Malleability: S' = S + L is a different encoding of the same signature.
    const data = `${b64u(header)}.${b64u(payload)}`
    const sig = ed25519.sign(new TextEncoder().encode(data), k0.privateKey)
    const L = 2n ** 252n + 27742317777372353535851937790883648493n
    let s = 0n
    for (let i = 31; i >= 0; i--) {
      s = (s << 8n) | BigInt(sig[32 + i])
    }
    const malleable = new Uint8Array(sig)
    let sPrime = s + L
    for (let i = 0; i < 32; i++) {
      malleable[32 + i] = Number(sPrime & 0xffn)
      sPrime >>= 8n
    }
    expect(sPrime).toBe(0n) // S + L still fits in 32 bytes

    const methods = registryFor([inception])
    let malleableResult: string
    try {
      await verifyToken(`${data}.${b64uBytes(malleable)}`, { methods })
      malleableResult = 'ACCEPTED'
    } catch (error) {
      malleableResult = error instanceof Error ? error.message : String(error)
    }
    // CONTROL: the untouched signature over the very same data verifies (throws if it does not).
    await verifyToken(`${data}.${b64uBytes(sig)}`, { methods })

    expect(wrongKey).not.toBe('ACCEPTED')
    expect(malleableResult, 'S+L malleability').not.toBe('ACCEPTED')
  })
})
