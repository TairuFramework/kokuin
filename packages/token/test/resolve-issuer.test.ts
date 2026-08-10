import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, it } from 'vitest'

import { createInMemoryDIDCache } from '../src/cache.js'
import {
  CODECS,
  getDID,
  IssuerKeyNotFoundError,
  isIssuerKeyNotFoundError,
  isUnresolvableIssuerError,
  resolveIssuer,
  resolveIssuerWithDoc,
  UnresolvableIssuerError,
} from '../src/did.js'
import type { DIDMethodResolver } from '../src/method.js'
import { encodeMultibase } from '../src/multibase.js'
import { encodePeer4 } from '../src/peer4.js'

describe('resolveIssuer', () => {
  it('resolves a did:key issuer to alg + pubkey without a resolver', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const did = getDID(CODECS.EdDSA, pub)
    const [alg, key] = await resolveIssuer(did)
    expect(alg).toBe('EdDSA')
    expect(key).toEqual(pub)
  })

  it('resolves a did:peer:4 short-form issuer via cache + kid', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { shortForm, doc } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    const cache = createInMemoryDIDCache()
    await cache.set(shortForm, doc)
    const resolver = (did: string) => cache.get(did)
    const [alg, key] = await resolveIssuer(shortForm, { kid: '#key-0' }, resolver)
    expect(alg).toBe('EdDSA')
    expect(key).toEqual(pub)
  })

  it('throws UnknownDID when peer:4 short form is unresolvable', async () => {
    await expect(
      resolveIssuer('did:peer:4zAAAAA', { kid: '#key-0' }, () => undefined),
    ).rejects.toThrow(/Unknown DID/)
  })

  it('falls back to first authentication entry when kid missing', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { shortForm, doc } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    const resolver = (did: string) => (did === shortForm ? doc : undefined)
    const [alg, key] = await resolveIssuer(shortForm, {}, resolver)
    expect(alg).toBe('EdDSA')
    expect(key).toEqual(pub)
  })

  it('throws KidNotFound when kid does not exist in doc', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { shortForm, doc } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    const resolver = (did: string) => (did === shortForm ? doc : undefined)
    await expect(resolveIssuer(shortForm, { kid: '#missing' }, resolver)).rejects.toThrow(
      /KidNotFound/,
    )
  })

  it('rejects a kid that is only an assertionMethod, not authentication', async () => {
    const authPriv = ed25519.utils.randomSecretKey()
    const assertPriv = ed25519.utils.randomSecretKey()
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const multibaseFor = (priv: Uint8Array) => {
      const pub = ed25519.getPublicKey(priv)
      const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
      taggedPub.set(ed25519Codec, 0)
      taggedPub.set(pub, ed25519Codec.length)
      return encodeMultibase(taggedPub)
    }
    const { shortForm, doc } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-0', type: 'Multikey', publicKeyMultibase: multibaseFor(authPriv) },
        { id: '#key-1', type: 'Multikey', publicKeyMultibase: multibaseFor(assertPriv) },
      ],
      authentication: ['#key-0'],
      assertionMethod: ['#key-1'],
    })
    const resolver = (did: string) => (did === shortForm ? doc : undefined)
    // The assertion-only key must not be usable to sign/verify a token.
    await expect(resolveIssuer(shortForm, { kid: '#key-1' }, resolver)).rejects.toThrow(
      /not an authentication method/,
    )
    // The authentication key still resolves.
    const [alg] = await resolveIssuer(shortForm, { kid: '#key-0' }, resolver)
    expect(alg).toBe('EdDSA')
  })

  it('decodes a did:peer:4 long-form issuer inline without calling the resolver', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { longForm } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    let resolverCalled = false
    const resolver = () => {
      resolverCalled = true
      return undefined
    }
    const [alg, key] = await resolveIssuer(longForm, { kid: '#key-0' }, resolver)
    expect(resolverCalled).toBe(false)
    expect(alg).toBe('EdDSA')
    expect(key).toEqual(pub)
  })

  it('decodes long form inline even without a resolver', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { longForm } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    const [alg, key] = await resolveIssuer(longForm, { kid: '#key-0' })
    expect(alg).toBe('EdDSA')
    expect(key).toEqual(pub)
  })
})

describe('resolveIssuerWithDoc', () => {
  it('returns the decoded doc when iss is a long-form did:peer:4', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { longForm, shortForm, doc } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    const result = await resolveIssuerWithDoc(longForm, { kid: '#key-0' })
    expect(result.alg).toBe('EdDSA')
    expect(result.publicKey).toEqual(pub)
    expect(result.peer4Doc).toEqual({ shortForm, doc })
  })

  it('returns no peer4Doc for short-form resolved via resolver', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { shortForm, doc } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    const resolver = (did: string) => (did === shortForm ? doc : undefined)
    const result = await resolveIssuerWithDoc(shortForm, { kid: '#key-0' }, resolver)
    expect(result.peer4Doc).toEqual({ shortForm, doc })
  })

  it('verifies hash-binding of resolver-returned doc and throws on mismatch', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const fakeShortForm = 'did:peer:4zAAAAAAAAAAAAAAAAAAAAAA'
    const resolver = () => ({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    await expect(resolveIssuerWithDoc(fakeShortForm, { kid: '#key-0' }, resolver)).rejects.toThrow(
      /hash mismatch/i,
    )
  })

  it('classifies a resolver that throws exactly like one that returns nothing', async () => {
    // Throwing is the normal style for a network-backed resolver, so a caller that fails closed
    // on `UnresolvableIssuerError` must see both the same way — otherwise the guarantee holds
    // only for resolvers that signal failure by returning `undefined`.
    const thrown = await resolveIssuer('did:peer:4zAAAAA', { kid: '#key-0' }, () => {
      throw new Error('ECONNREFUSED')
    }).catch((error: unknown) => error)
    expect(isUnresolvableIssuerError(thrown)).toBe(true)
    expect((thrown as UnresolvableIssuerError).cause).toBeInstanceOf(Error)

    const empty = await resolveIssuer('did:peer:4zAAAAA', { kid: '#key-0' }, () => undefined).catch(
      (error: unknown) => error,
    )
    expect(isUnresolvableIssuerError(empty)).toBe(true)
  })

  it('types a resolver that answers with a mismatched doc as unresolvable', async () => {
    // The resolver answered, but its answer does not hash to the DID that was asked for, so no
    // key was obtained. Left an ordinary error this would read as "not revoked" to a caller that
    // fails closed only on this type — a broken or lying resolver silently suppressing
    // revocation, which is the fail-open this type exists to remove.
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const resolver = () => ({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-0', type: 'Multikey', publicKeyMultibase: encodeMultibase(taggedPub) },
      ],
      authentication: ['#key-0'],
    })
    const thrown = await resolveIssuerWithDoc(
      'did:peer:4zAAAAAAAAAAAAAAAAAAAAAA',
      { kid: '#key-0' },
      resolver,
    ).catch((error: unknown) => error)
    expect(isUnresolvableIssuerError(thrown)).toBe(true)
    // The message is unchanged, so a caller reading it still learns what went wrong.
    expect((thrown as Error).message).toMatch(/hash mismatch/i)
  })

  it('types a resolver that answers with an oversized doc as unresolvable', async () => {
    // Same reasoning as the mismatch above: the size bound rejects the answer, so no key was
    // obtained, so the issuer is unresolved. The entry-count arm is used here because it trips
    // in O(1) without building a 4KB document.
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const ed25519Codec = new Uint8Array([0xed, 0x01])
    const taggedPub = new Uint8Array(ed25519Codec.length + pub.length)
    taggedPub.set(ed25519Codec, 0)
    taggedPub.set(pub, ed25519Codec.length)
    const publicKeyMultibase = encodeMultibase(taggedPub)
    const { shortForm } = encodePeer4({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase }],
      authentication: ['#key-0'],
    })
    // Resolves the *correct* short form, so the hash check is not what rejects this.
    const resolver = () => ({
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: Array.from({ length: 500 }, (_, i) => ({
        id: `#key-${i}`,
        type: 'Multikey',
        publicKeyMultibase,
      })),
      authentication: ['#key-0'],
    })
    const thrown = await resolveIssuerWithDoc(shortForm, { kid: '#key-0' }, resolver).catch(
      (error: unknown) => error,
    )
    expect(isUnresolvableIssuerError(thrown)).toBe(true)
    expect((thrown as Error).message).toMatch(/too many verification methods/i)
  })

  it("does not type a method resolver's key-not-found as unresolvable", async () => {
    // A method that has the issuer and does not have the named key is reporting the same thing
    // `resolveKidOrAuth` reports for a did:peer:4 document — the issuer resolved, the token is
    // bad. Wrapping it as unresolvable would let `kid`, an unauthenticated header field, decide
    // whether a caller that fails closed on that type denies.
    const did = 'did:kokuin:zTestProfile'
    const methods: Array<DIDMethodResolver> = [
      {
        method: 'kokuin',
        resolve: async (_did: string, header: { kid?: string }) => {
          if (header.kid != null) {
            throw new IssuerKeyNotFoundError(`no such key: ${header.kid}`)
          }
          throw new Error(`Unknown DID: ${did}`)
        },
      },
    ]

    const keyNotFound = await resolveIssuer(did, { kid: '#nope' }, undefined, methods).catch(
      (error: unknown) => error,
    )
    expect(isIssuerKeyNotFoundError(keyNotFound)).toBe(true)
    expect(isUnresolvableIssuerError(keyNotFound)).toBe(false)
    // Rethrown as thrown, so the message a caller reads is the method's own.
    expect((keyNotFound as Error).message).toBe('no such key: #nope')

    // Control: everything else the same resolver throws is still unresolvable, so the assertion
    // above is the classification and not this path having stopped wrapping altogether.
    const unresolvable = await resolveIssuer(did, {}, undefined, methods).catch(
      (error: unknown) => error,
    )
    expect(isUnresolvableIssuerError(unresolvable)).toBe(true)
    expect(isIssuerKeyNotFoundError(unresolvable)).toBe(false)
  })

  it('brands the key-not-found error too, and keeps the two guards disjoint', async () => {
    expect(new IssuerKeyNotFoundError('x').brand).toBe(IssuerKeyNotFoundError.brand)
    expect(isIssuerKeyNotFoundError(new Error('Invalid signature'))).toBe(false)
    // Neither guard may fire on the other's error, or the two classifications collapse.
    expect(isUnresolvableIssuerError(new IssuerKeyNotFoundError('x'))).toBe(false)
    expect(isIssuerKeyNotFoundError(new UnresolvableIssuerError('x'))).toBe(false)
  })

  it('brands the error so a duplicated copy of this package still matches', async () => {
    const thrown = await resolveIssuer('did:example:nobody').catch((error: unknown) => error)
    expect(isUnresolvableIssuerError(thrown)).toBe(true)
    // What a second copy of the class would compare against — a string, not an identity.
    expect((thrown as UnresolvableIssuerError).brand).toBe(UnresolvableIssuerError.brand)
    // The guard must not fire on an unrelated error that merely happens to be an Error.
    expect(isUnresolvableIssuerError(new Error('Invalid signature'))).toBe(false)
  })
})
