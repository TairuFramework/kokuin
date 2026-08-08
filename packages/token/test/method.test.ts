import { describe, expect, test } from 'vitest'

import { resolveIssuerWithDoc } from '../src/did.js'
import { type DIDMethodResolver, findMethodResolver } from '../src/method.js'

const publicKey = new Uint8Array(32).fill(7)

const kokuinResolver: DIDMethodResolver = {
  method: 'kokuin',
  resolve: async (did) => {
    if (did !== 'did:kokuin:zABC') {
      throw new Error(`Unknown DID: ${did}`)
    }
    return { alg: 'EdDSA', publicKey }
  },
}

describe('findMethodResolver()', () => {
  test('matches on the method segment', () => {
    expect(findMethodResolver([kokuinResolver], 'did:kokuin:zABC')).toBe(kokuinResolver)
  })

  test('returns undefined for an unregistered method', () => {
    expect(findMethodResolver([kokuinResolver], 'did:example:1')).toBeUndefined()
  })

  test('returns undefined for a malformed DID rather than throwing', () => {
    expect(findMethodResolver([kokuinResolver], 'not-a-did')).toBeUndefined()
  })

  test('does not match a method that is only a prefix of the registered one', () => {
    expect(findMethodResolver([kokuinResolver], 'did:kokuinx:zABC')).toBeUndefined()
  })
})

describe('resolveIssuerWithDoc() with an injected method', () => {
  test('delegates an unknown method to its resolver', async () => {
    const result = await resolveIssuerWithDoc('did:kokuin:zABC', {}, undefined, [kokuinResolver])
    expect(result.alg).toBe('EdDSA')
    expect(result.publicKey).toEqual(publicKey)
  })

  test('still resolves did:key without any registry', async () => {
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const result = await resolveIssuerWithDoc(did)
    expect(result.alg).toBe('EdDSA')
    expect(result.publicKey.length).toBe(32)
  })

  test('a registered method takes precedence over the built-in did:key path', async () => {
    const override: DIDMethodResolver = {
      method: 'key',
      resolve: async () => ({ alg: 'EdDSA', publicKey }),
    }
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const result = await resolveIssuerWithDoc(did, {}, undefined, [override])
    expect(result.publicKey).toEqual(publicKey)
  })

  test('an unknown method with no registry reports the DID, not a codec error', async () => {
    await expect(resolveIssuerWithDoc('did:kokuin:zABC')).rejects.toThrow(/did:kokuin:zABC/)
  })
})
