import { describe, expect, it } from 'vitest'

import {
  assertDocWithinMaxSize,
  type DIDDoc,
  decodePeer4,
  encodePeer4,
  getPeer4ShortForm,
  isPeer4,
  validateDIDDoc,
} from '../src/peer4.js'

describe('validateDIDDoc', () => {
  it('accepts a minimal valid doc', () => {
    expect(
      validateDIDDoc({
        '@context': ['https://www.w3.org/ns/did/v1'],
        verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase: 'z6MkAbc' }],
        authentication: ['#key-0'],
      }),
    ).toBe(true)
  })

  it('rejects a doc missing verificationMethod', () => {
    expect(
      validateDIDDoc({
        '@context': ['https://www.w3.org/ns/did/v1'],
      }),
    ).toBe(false)
  })

  it('rejects a verificationMethod entry missing publicKeyMultibase', () => {
    expect(
      validateDIDDoc({
        '@context': ['https://www.w3.org/ns/did/v1'],
        verificationMethod: [{ id: '#key-0', type: 'Multikey' }],
      }),
    ).toBe(false)
  })

  it('accepts a doc with keyAgreement entries', () => {
    expect(
      validateDIDDoc({
        '@context': ['https://www.w3.org/ns/did/v1'],
        verificationMethod: [
          { id: '#key-0', type: 'Multikey', publicKeyMultibase: 'z6MkAbc' },
          { id: '#key-1', type: 'Multikey', publicKeyMultibase: 'z6LSdef' },
        ],
        authentication: ['#key-0'],
        keyAgreement: ['#key-1'],
      }),
    ).toBe(true)
  })
})

describe('encodePeer4', () => {
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase: 'z6MkAbc' }],
    authentication: ['#key-0'],
  }

  it('rejects an invalid doc on encode', () => {
    expect(() => encodePeer4({ '@context': [] } as unknown as DIDDoc)).toThrow(/schema validation/)
  })

  it('produces a long form starting with did:peer:4', () => {
    const { longForm } = encodePeer4(doc)
    expect(longForm.startsWith('did:peer:4z')).toBe(true)
  })

  it('produces a short form prefix that matches the long form', () => {
    const { longForm, shortForm } = encodePeer4(doc)
    expect(longForm.startsWith(`${shortForm}:`)).toBe(true)
  })

  it('is deterministic — same doc → same long form', () => {
    const a = encodePeer4(doc)
    const b = encodePeer4({ ...doc })
    expect(a.longForm).toBe(b.longForm)
  })

  it('produces different output for different docs', () => {
    const a = encodePeer4(doc)
    const b = encodePeer4({ ...doc, authentication: [] })
    expect(a.longForm).not.toBe(b.longForm)
  })
})

describe('decodePeer4', () => {
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase: 'z6MkAbc' }],
    authentication: ['#key-0'],
  }

  it('decodes a long form back to the original doc', () => {
    const { longForm } = encodePeer4(doc)
    const decoded = decodePeer4(longForm)
    expect(decoded.doc).toEqual(doc)
    expect(decoded.shortForm).toBe(longForm.split(':').slice(0, 3).join(':'))
  })

  it('rejects a long form with mismatched hash', () => {
    const { longForm } = encodePeer4(doc)
    const idx = longForm.indexOf(':z', 'did:peer:4'.length) + 2
    const tampered = `${longForm.slice(0, idx)}A${longForm.slice(idx + 1)}`
    expect(() => decodePeer4(tampered)).toThrow(/hash mismatch/i)
  })

  it('rejects a short form passed to decodePeer4', () => {
    const { shortForm } = encodePeer4(doc)
    expect(() => decodePeer4(shortForm)).toThrow(/long form/i)
  })

  it('rejects a non-peer:4 DID', () => {
    expect(() => decodePeer4('did:key:z6MkAbc')).toThrow(/Invalid did:peer:4/)
  })

  it('rejects an oversized doc', () => {
    const big = { ...doc, padding: 'x'.repeat(200) }
    const { longForm } = encodePeer4(big)
    expect(() => decodePeer4(longForm, { maxDocSize: 100 })).toThrow(/doc too large/i)
  })
})

describe('decodePeer4 bounds', () => {
  // 4 KiB default doc + 2 multicodec bytes, times the base58 expansion ratio, plus slack.
  const maxEncoded = Math.ceil((4 * 1024 + 2) * 1.3658) + 8

  const validDoc: DIDDoc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [
      { id: '#key-0', type: 'Multikey', publicKeyMultibase: 'z6MkAbc' },
      { id: '#key-1', type: 'Multikey', publicKeyMultibase: 'z6MkDef' },
      { id: '#key-2', type: 'Multikey', publicKeyMultibase: 'z6MkGhi' },
    ],
    authentication: ['#key-0'],
    keyAgreement: ['#key-1'],
    assertionMethod: ['#key-2'],
  }

  it('rejects an oversized hash segment before decoding it', () => {
    // '0' is not in the base58 alphabet: without the length check, decodeMultibase throws.
    const longForm = `did:peer:4z${'0'.repeat(70)}:z6MkAbc`
    expect(() => decodePeer4(longForm)).toThrow('did:peer:4 hash too large')
  })

  it('rejects an oversized encoded doc before decoding it', () => {
    const hash = `z${'1'.repeat(47)}`
    const encodedDoc = `z${'0'.repeat(maxEncoded)}`
    const longForm = `did:peer:4${hash}:${encodedDoc}`
    expect(() => decodePeer4(longForm)).toThrow(/encoded doc too large/)
  })

  it('decodes a realistic three-key document', () => {
    const { longForm } = encodePeer4(validDoc)
    expect(decodePeer4(longForm).doc).toEqual(validDoc)
  })

  it('honours a smaller maxDocSize override', () => {
    const { longForm } = encodePeer4(validDoc)
    expect(() => decodePeer4(longForm, { maxDocSize: 64 })).toThrow(/too large/)
  })

  it('honours a larger maxDocSize override', () => {
    const { longForm } = encodePeer4(validDoc)
    expect(decodePeer4(longForm, { maxDocSize: 8 * 1024 }).doc).toEqual(validDoc)
  })
})

describe('isPeer4 / getPeer4ShortForm', () => {
  it('detects peer:4 DIDs', () => {
    expect(isPeer4('did:peer:4zAbc')).toBe(true)
    expect(isPeer4('did:key:z6Mk')).toBe(false)
  })

  it('rejects did:peer:4 without z prefix on hash', () => {
    expect(isPeer4('did:peer:40foo')).toBe(false)
    expect(isPeer4('did:peer:4')).toBe(false)
  })

  it('extracts the short form from a long form', () => {
    const { longForm, shortForm } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#k', type: 'Multikey', publicKeyMultibase: 'z6Mk' }],
    })
    expect(getPeer4ShortForm(longForm)).toBe(shortForm)
    expect(getPeer4ShortForm(shortForm)).toBe(shortForm)
  })
})

describe('assertDocWithinMaxSize', () => {
  const entry = { id: '#key-0', type: 'Multikey', publicKeyMultibase: 'z6MkAbc' }

  function docWithEntries(count: number): DIDDoc {
    return {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: Array.from({ length: count }, (_, i) => ({ ...entry, id: `#key-${i}` })),
    }
  }

  it('accepts a doc under both bounds', () => {
    const doc: DIDDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [entry],
      authentication: ['#key-0'],
    }
    expect(() => assertDocWithinMaxSize(doc)).not.toThrow()
  })

  it('rejects on entry count before measuring the serialized doc', () => {
    // 4 KiB default / 40 bytes minimum per entry = 103 entries allowed.
    expect(() => assertDocWithinMaxSize(docWithEntries(104))).toThrow(
      'did:peer:4 resolver doc has too many verification methods: 104 > 103',
    )
  })

  it('scales the entry cap with maxSize', () => {
    // 200 / 40 = 5 entries allowed.
    expect(() => assertDocWithinMaxSize(docWithEntries(6), 200)).toThrow(
      'did:peer:4 resolver doc has too many verification methods: 6 > 5',
    )
  })

  it('still reports the byte-size error for a doc with few but huge entries', () => {
    const doc: DIDDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ ...entry, publicKeyMultibase: `z${'1'.repeat(8 * 1024)}` }],
    }
    expect(() => assertDocWithinMaxSize(doc)).toThrow(/did:peer:4 resolver doc too large/)
  })
})
