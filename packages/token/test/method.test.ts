import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import {
  isIssuerKeyNotFoundError,
  isUnresolvableIssuerError,
  resolveIssuerWithDoc,
} from '../src/did.js'
import { type DIDMethodResolver, findMethodResolver } from '../src/method.js'
import { encodeMultibase } from '../src/multibase.js'
import { encodePeer4 } from '../src/peer4.js'

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

describe('DIDMethodResolver.resolveAgreementKey', () => {
  test('is optional -- a resolver may omit it entirely', () => {
    const resolverWithoutAgreement: DIDMethodResolver = {
      method: 'kokuin',
      resolve: async () => ({ alg: 'EdDSA', publicKey }),
    }
    expect(resolverWithoutAgreement.resolveAgreementKey).toBeUndefined()
  })

  test('resolves the agreement key set when the method supports it', async () => {
    const agreementKey = new Uint8Array(32).fill(9)
    const resolverWithAgreement: DIDMethodResolver = {
      method: 'kokuin',
      resolve: async () => ({ alg: 'EdDSA', publicKey }),
      resolveAgreementKey: async () => [{ alg: 'X25519', publicKey: agreementKey }],
    }
    const keys = await resolverWithAgreement.resolveAgreementKey?.('did:kokuin:zABC')
    expect(keys).toEqual([{ alg: 'X25519', publicKey: agreementKey }])
  })
})

describe('DIDMethodResolver.resolveHistoric', () => {
  const historicKey = new Uint8Array(32).fill(11)
  const bothMembers: DIDMethodResolver = {
    method: 'kokuin',
    resolve: async () => ({ alg: 'EdDSA', publicKey }),
    resolveHistoric: async () => ({ alg: 'EdDSA', publicKey: historicKey }),
  }

  test('the default asks `resolve`, never `resolveHistoric`', async () => {
    const result = await resolveIssuerWithDoc({
      iss: 'did:kokuin:zABC',
      header: {},
      resolver: undefined,
      methods: [bothMembers],
    })
    expect(result.publicKey).toEqual(publicKey)
  })

  test('`historic: true` asks `resolveHistoric`, and nothing else does', async () => {
    // The two members answer with different keys, so this cannot pass by both being consulted.
    const result = await resolveIssuerWithDoc({
      iss: 'did:kokuin:zABC',
      header: {},
      resolver: undefined,
      methods: [bothMembers],
      historic: true,
    })
    expect(result.publicKey).toEqual(historicKey)
    // An explicit `false` and an absent `mode` are the same ask.
    const off = await resolveIssuerWithDoc({
      iss: 'did:kokuin:zABC',
      header: {},
      resolver: undefined,
      methods: [bothMembers],
      historic: false,
    })
    expect(off.publicKey).toEqual(publicKey)
  })

  test('a resolver that omits it refuses the historic ask rather than falling back', async () => {
    // Fail closed at the call site. A resolver written against the previous contract has a
    // *permissive* `resolve` — the whole-generation scan — so answering the historic ask from it
    // would be exactly the behaviour the split removed, silently and for every such resolver.
    await expect(
      resolveIssuerWithDoc({
        iss: 'did:kokuin:zABC',
        header: {},
        resolver: undefined,
        methods: [kokuinResolver],
        historic: true,
      }),
    ).rejects.toThrow(/cannot resolve historic keys/)
    // Control: the identical registry entry, the identical DID, answering the non-historic ask.
    // The refusal above is the missing member and not the resolver being unusable.
    const control = await resolveIssuerWithDoc({
      iss: 'did:kokuin:zABC',
      header: {},
      resolver: undefined,
      methods: [kokuinResolver],
    })
    expect(control.publicKey).toEqual(publicKey)
  })

  test('the refusal is an UnresolvableIssuerError — "could not check", not "checked and bad"', async () => {
    // A fail-closed caller keys on this type. Nothing was learned about the artefact: the method
    // simply cannot answer the question that was asked.
    const error = await resolveIssuerWithDoc({
      iss: 'did:kokuin:zABC',
      header: {},
      resolver: undefined,
      methods: [kokuinResolver],
      historic: true,
    }).then(
      () => undefined,
      (cause: unknown) => cause,
    )
    expect(isUnresolvableIssuerError(error)).toBe(true)
    expect(isIssuerKeyNotFoundError(error)).toBe(false)
  })

  test('`did:key` ignores the mode entirely — its key is in the identifier', async () => {
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const historic = await resolveIssuerWithDoc({
      iss: did,
      header: {},
      resolver: undefined,
      methods: undefined,
      historic: true,
    })
    const current = await resolveIssuerWithDoc({ iss: did })
    expect(historic.publicKey).toEqual(current.publicKey)
  })
})

describe('resolveIssuerWithDoc() with an injected method', () => {
  test('delegates an unknown method to its resolver', async () => {
    const result = await resolveIssuerWithDoc({
      iss: 'did:kokuin:zABC',
      header: {},
      resolver: undefined,
      methods: [kokuinResolver],
    })
    expect(result.alg).toBe('EdDSA')
    expect(result.publicKey).toEqual(publicKey)
  })

  test('still resolves did:key without any registry', async () => {
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const result = await resolveIssuerWithDoc({ iss: did })
    expect(result.alg).toBe('EdDSA')
    expect(result.publicKey.length).toBe(32)
  })

  test('a registered method takes precedence over the built-in did:key path', async () => {
    const override: DIDMethodResolver = {
      method: 'key',
      resolve: async () => ({ alg: 'EdDSA', publicKey }),
    }
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const result = await resolveIssuerWithDoc({
      iss: did,
      header: {},
      resolver: undefined,
      methods: [override],
    })
    expect(result.publicKey).toEqual(publicKey)
  })

  test('an unknown method with no registry reports the DID, not a codec error', async () => {
    await expect(resolveIssuerWithDoc({ iss: 'did:kokuin:zABC' })).rejects.toThrow(
      /did:kokuin:zABC/,
    )
  })

  test('a registered method takes precedence over the built-in did:peer:4 path', async () => {
    // A long-form did:peer:4 the built-in path resolves successfully on its own, so a passing
    // assertion here can only mean the registry lookup won — not that the built-in path failed.
    const priv = ed25519.utils.randomSecretKey()
    const embeddedPub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + embeddedPub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(embeddedPub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { longForm } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })

    // findMethodResolver reads parts[1] of the DID: for `did:peer:4z...` that's `peer`.
    const override: DIDMethodResolver = {
      method: 'peer',
      resolve: async () => ({ alg: 'EdDSA', publicKey }),
    }

    const result = await resolveIssuerWithDoc({
      iss: longForm,
      header: { kid: '#key-0' },
      resolver: undefined,
      methods: [override],
    })
    expect(result.publicKey).toEqual(publicKey)
    expect(result.publicKey).not.toEqual(embeddedPub)
  })
})
