import {
  createIdentity,
  createInMemoryDIDCache,
  createSigningIdentityForDID,
  type DIDDoc,
  type DIDMethodResolver,
  type DIDString,
  decodePeer4,
  IssuerKeyNotFoundError,
  randomIdentity,
  randomPrivateKey,
  type SigningIdentity,
  stringifyToken,
  UnresolvableIssuerError,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { checkDelegationChain, createCapability } from '../src/index.js'
import {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
  type RevocationRecord,
} from '../src/revocation.js'

// A DID whose keys cannot be recovered from the identifier — the shape `did:kokuin:` has. The
// resolver is a hand-built fake, matching `test/method-registry.test.ts`: this package must not
// depend on `@kokuin/controller`, and a real folded log would prove nothing extra about the
// option threading.
const profileDID = 'did:kokuin:zTestProfile' as DIDString

function buildProfile(): { identity: SigningIdentity; resolver: DIDMethodResolver } {
  const identity = createSigningIdentityForDID(profileDID, randomPrivateKey())
  const resolver: DIDMethodResolver = {
    method: 'kokuin',
    resolve: async (did: string) => {
      if (did !== profileDID) {
        throw new Error(`Unknown DID: ${did}`)
      }
      return { alg: 'EdDSA', publicKey: identity.publicKey }
    },
    // A fake with one fixed key, so the two questions genuinely coincide — the alias
    // `DIDMethodResolver.resolveHistoric` documents for a method whose key set never changes. It
    // has to be published all the same: `checkCapability` verifies archived material and asks for
    // it, and its absence is refused rather than answered from `resolve`.
    resolveHistoric: async (did: string) => {
      if (did !== profileDID) {
        throw new Error(`Unknown DID: ${did}`)
      }
      return { alg: 'EdDSA', publicKey: identity.publicKey }
    },
  }
  return { identity, resolver }
}

describe('revocation', () => {
  test('createMemoryRevocationBackend stores signed records by jti', async () => {
    const signer = randomIdentity()
    const backend = createMemoryRevocationBackend()
    expect(await backend.get('some-jti')).toBeUndefined()
    const record = await createRevocationRecord(signer, 'some-jti')
    await backend.add(record)
    expect(await backend.get('some-jti')).toBeDefined()
  })

  test('add rejects a record with a forged signature', async () => {
    const signer = randomIdentity()
    const backend = createMemoryRevocationBackend()
    const record = await createRevocationRecord(signer, 'cap-1')
    const forged = { ...record, signature: 'AAAA' }
    await expect(backend.add(forged)).rejects.toThrow()
    expect(await backend.get('cap-1')).toBeUndefined()
  })

  test('createRevocationChecker returns a VerifyTokenHook', () => {
    const backend = createMemoryRevocationBackend()
    const checker = createRevocationChecker(backend)
    expect(typeof checker).toBe('function')
  })

  test('checker passes for non-revoked token', async () => {
    const backend = createMemoryRevocationBackend()
    const checker = createRevocationChecker(backend)

    const signer = randomIdentity()
    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-1',
    })

    // Should not throw
    await checker(capability, stringifyToken(capability))
  })

  test('checker rejects a token revoked by its own issuer', async () => {
    const backend = createMemoryRevocationBackend()
    const checker = createRevocationChecker(backend)

    const signer = randomIdentity()
    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-revoked',
    })

    await backend.add(await createRevocationRecord(signer, 'cap-revoked'))

    await expect(checker(capability, stringifyToken(capability))).rejects.toThrow('revoked')
  })

  test('a record signed by a key the issuer has denied still revokes', async () => {
    // Revoking a leaked key stops every record that key signed from verifying. Ignoring those, as
    // an unverifiable record otherwise is, would make the remedy for a compromise resurrect every
    // capability the key had revoked — so a record naming a key the issuer *published and denied*
    // is honoured. The control below is the case that must stay ignored.
    const identity = createSigningIdentityForDID(profileDID, randomPrivateKey())
    const liveKid = '#zLiveAuthorityKey'
    const deniedKid = '#zLeakedAuthorityKey'
    // A `kid` outside the key set is an error, never a fallback — so the fake answers for exactly
    // one key and refuses every other, which is what makes the two failing records below fail the
    // *same* way. Without that, the control naming an unknown key would verify against the live
    // key and revoke through the ordinary path, certifying nothing about the branch under test.
    const keyFor = async (did: string, header?: { kid?: string }) => {
      if (did !== profileDID) {
        throw new Error(`Unknown DID: ${did}`)
      }
      if (header?.kid != null && header.kid !== liveKid) {
        throw new IssuerKeyNotFoundError(
          `kid names a key the controller does not hold: ${header.kid}`,
        )
      }
      return { alg: 'EdDSA' as const, publicKey: identity.publicKey }
    }
    const resolver: DIDMethodResolver = {
      method: 'kokuin',
      resolve: keyFor,
      resolveHistoric: keyFor,
      resolveDenySet: async () => new Set([deniedKid]),
    }
    const options = { methods: [resolver] }

    const capability = await createCapability(
      identity,
      { sub: profileDID, aud: 'did:key:bob', act: '*', res: '*', jti: 'grant-denied-key' },
      undefined,
      options,
    )

    const bySignedKey = async (kid: string): Promise<RevocationRecord> =>
      (await identity.signToken(
        { jti: 'grant-denied-key', rev: true, iat: Math.floor(Date.now() / 1000) },
        { header: { kid } },
      )) as RevocationRecord

    // The backend verifies on the way in, so a record signed by an already-denied key could not be
    // stored through it. This is a record stored while the key was live, read back afterwards.
    const stored = await bySignedKey(deniedKid)
    const denied = createRevocationChecker({ add: async () => {}, get: async () => stored }, options)
    await expect(denied(capability, stringifyToken(capability))).rejects.toThrow('revoked')

    // CONTROL — a key this DID never published is a forgery, and honouring it would let anyone
    // deny every capability the profile ever issued by planting one record per `jti`.
    const planted = await bySignedKey('#zNeverPublished')
    const forged = createRevocationChecker(
      { add: async () => {}, get: async () => planted },
      options,
    )
    await expect(forged(capability, stringifyToken(capability))).resolves.toBeUndefined()
  })

  test('a revocation signed by a different issuer does not revoke the token', async () => {
    const backend = createMemoryRevocationBackend()
    const checker = createRevocationChecker(backend)

    const issuer = randomIdentity()
    const attacker = randomIdentity()
    const capability = await createCapability(issuer, {
      sub: issuer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-target',
    })

    // The attacker signs a revocation for the victim's jti — a valid signature, but wrong issuer.
    await backend.add(await createRevocationRecord(attacker, 'cap-target'))

    // Must NOT revoke: only the token's own issuer may revoke it.
    await checker(capability, stringifyToken(capability))
  })

  test('checker re-verifies and ignores a forged record from an untrusting backend', async () => {
    const issuer = randomIdentity()
    const capability = await createCapability(issuer, {
      sub: issuer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-forged',
    })

    // A valid record signed by the real issuer, then tampered — a backend that stores without
    // verifying would return it. The checker must not trust it.
    const genuine = await createRevocationRecord(issuer, 'cap-forged')
    const forged = { ...genuine, signature: 'AAAA' }
    const untrustingBackend = {
      async add() {},
      async get() {
        return forged
      },
    }
    const checker = createRevocationChecker(untrustingBackend)

    // Must NOT revoke: the signature is invalid.
    await checker(capability, stringifyToken(capability))
  })

  test('checker integrates with checkDelegationChain', async () => {
    const backend = createMemoryRevocationBackend()
    const checker = createRevocationChecker(backend)

    const root = randomIdentity()
    const device = randomIdentity()

    const delegation = await createCapability(root, {
      sub: root.id,
      aud: device.id,
      act: '*',
      res: '*',
      jti: 'delegation-1',
    })

    const subDelegation = await createCapability(
      device,
      {
        sub: root.id,
        aud: 'did:key:service',
        act: 'read',
        res: 'data/*',
        jti: 'sub-delegation-1',
      },
      undefined,
      { parentCapability: stringifyToken(delegation) },
    )

    // Valid before revocation
    await checkDelegationChain(subDelegation.payload, [stringifyToken(delegation)], {
      verifyToken: checker,
    })

    // Revoke root delegation (signed by root, the delegation's issuer)
    await backend.add(await createRevocationRecord(root, 'delegation-1'))

    // Should fail after revocation
    await expect(
      checkDelegationChain(subDelegation.payload, [stringifyToken(delegation)], {
        verifyToken: checker,
      }),
    ).rejects.toThrow('revoked')
  })

  test('createRevocationRecord produces a signed revocation', async () => {
    const signer = randomIdentity()
    const record = await createRevocationRecord(signer, 'cap-to-revoke')
    expect(record.payload.jti).toBe('cap-to-revoke')
    expect(record.payload.iss).toBe(signer.id)
    expect(record.payload.rev).toBe(true)
    expect(typeof record.payload.iat).toBe('number')
    expect(typeof record.signature).toBe('string')
  })

  test('a did:peer:4 signer produces a revocation record a cold verifier can check', async () => {
    // Two keys means chooseMethod picks peer:4 on its own — the shape a KEM key produces.
    const signer = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const record = await createRevocationRecord(signer, 'cap-peer4')
    // A revocation record carries no aud, so its iss must carry the document with it.
    expect(record.payload.iss).toBe(signer.longForm)

    // A backend that has never seen this signer must still verify and store the record.
    const backend = createMemoryRevocationBackend()
    await backend.add(record)

    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-peer4',
    })
    const checker = createRevocationChecker(backend)
    await expect(checker(capability, stringifyToken(capability))).rejects.toThrow('revoked')

    // The failure mode this replaces, pinned: forcing the old short-form iss makes the same
    // record unverifiable by the same cold backend.
    const shortFormRecord = (await signer.signToken(
      { jti: 'cap-peer4-short', rev: true, iat: Math.floor(Date.now() / 1000) },
      { embedLongForm: false },
    )) as typeof record
    await expect(backend.add(shortFormRecord)).rejects.toThrow(/Unknown DID/)
  })

  // A short-form did:peer:4 record carries no document, so it needs a resolver. Fail-closed makes
  // that a hard rejection rather than a silent pass, so `RevocationOptions` has to offer a way in.
  async function buildShortFormRecord(jti: string): Promise<{
    signer: Awaited<ReturnType<typeof createIdentity>>
    record: RevocationRecord
    doc: DIDDoc
  }> {
    const signer = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const record = (await signer.signToken(
      { jti, rev: true, iat: Math.floor(Date.now() / 1000) },
      { embedLongForm: false },
    )) as RevocationRecord
    // Pinned: without this the record would carry its own document and need no resolver at all,
    // and the three tests below would not be exercising the resolver option.
    expect(record.payload.iss).toBe(signer.id)
    return { signer, record, doc: decodePeer4(signer.longForm).doc }
  }

  test('a short-form did:peer:4 record revokes when the checker is given a resolver', async () => {
    const { signer, record, doc } = await buildShortFormRecord('cap-shortform')
    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-shortform',
    })
    const resolver = (did: string) => (did === signer.id ? doc : undefined)

    const backend = createMemoryRevocationBackend({ resolver })
    await backend.add(record)
    const checker = createRevocationChecker(backend, { resolver })
    await expect(checker(capability, stringifyToken(capability))).rejects.toThrow('revoked')

    // Control: the same record and the same backend contents, with no resolver on the checker,
    // fail closed instead — so the revocation above is the resolver option doing its job.
    const blind = createRevocationChecker(backend)
    await expect(checker(capability, stringifyToken(capability))).rejects.toThrow('revoked')
    await expect(blind(capability, stringifyToken(capability))).rejects.toThrow(
      UnresolvableIssuerError,
    )
  })

  test('a short-form did:peer:4 record revokes when resolution comes only from the cache', async () => {
    // `cache` is the third resolution input and the only one with no resolver behind it here:
    // `verifyToken` composes the cache into its effective resolver, so a pre-populated cache is
    // sufficient on its own. Without `cache` forwarded there is nothing to resolve the short form
    // and this fails closed instead of revoking.
    const { signer, record, doc } = await buildShortFormRecord('cap-cached')
    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-cached',
    })
    const cache = createInMemoryDIDCache()
    await cache.set(signer.id, doc)

    // Note: no `resolver` anywhere in this test, on either the backend or the checker.
    const backend = createMemoryRevocationBackend({ cache })
    await backend.add(record)
    const checker = createRevocationChecker(backend, { cache })
    await expect(checker(capability, stringifyToken(capability))).rejects.toThrow('revoked')

    // Control: an empty cache, everything else identical, fails closed — so the revocation above
    // is the cache being consulted and not some other path resolving the issuer.
    const blind = createRevocationChecker(backend, { cache: createInMemoryDIDCache() })
    await expect(blind(capability, stringifyToken(capability))).rejects.toThrow(
      UnresolvableIssuerError,
    )
  })

  test('a resolver that throws denies rather than silently passing', async () => {
    // The counterpart at the checker to the token-level classification test. This is the likeliest
    // real-world failure of the three — a network-backed resolver that is down — and if the throw
    // escaped as an ordinary error the checker would swallow it and report "not revoked".
    const { signer, record, doc } = await buildShortFormRecord('cap-throwing')
    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-throwing',
    })
    const backend = createMemoryRevocationBackend({ resolver: () => doc })
    await backend.add(record)

    const down = createRevocationChecker(backend, {
      resolver: () => {
        throw new Error('ECONNREFUSED')
      },
    })
    await expect(down(capability, stringifyToken(capability))).rejects.toThrow(
      UnresolvableIssuerError,
    )

    // The same path reached through the cache: `verifyToken` composes `cache.get` into the
    // effective resolver, so a cache that throws surfaces here identically.
    const brokenCache = createRevocationChecker(backend, {
      cache: {
        get: async () => {
          throw new Error('cache backend unavailable')
        },
        set: async () => {},
      },
    })
    await expect(brokenCache(capability, stringifyToken(capability))).rejects.toThrow(
      UnresolvableIssuerError,
    )

    // Control: a working resolver over the same record revokes, so the two denials above are the
    // failure being surfaced and not the record being unverifiable for some other reason.
    const up = createRevocationChecker(backend, { resolver: () => doc })
    await expect(up(capability, stringifyToken(capability))).rejects.toThrow('revoked')
  })

  test('a resolver answering with a mismatched doc denies rather than silently passing', async () => {
    // The resolver answers, but with a document that does not hash to the DID asked for. No key
    // is obtained, so revocation is unknown — and a broken or lying resolver must not be able to
    // suppress a revocation by reading as "not revoked".
    const { signer, record, doc } = await buildShortFormRecord('cap-mismatch')
    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-mismatch',
    })
    const backend = createMemoryRevocationBackend({ resolver: () => doc })
    await backend.add(record)

    // Some other identity's document, returned for this signer's short form.
    const other = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const lying = createRevocationChecker(backend, {
      resolver: () => decodePeer4(other.longForm).doc,
    })
    await expect(lying(capability, stringifyToken(capability))).rejects.toThrow(
      UnresolvableIssuerError,
    )
  })

  test('a resolver answering with an oversized doc denies rather than silently passing', async () => {
    const { signer, record, doc } = await buildShortFormRecord('cap-oversized')
    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-oversized',
    })
    const backend = createMemoryRevocationBackend({ resolver: () => doc })
    await backend.add(record)

    // Same document, inflated past the size bound. The bound rejects the answer, so no key is
    // obtained — identical outcome to the mismatch above.
    const oversized = {
      ...doc,
      verificationMethod: Array.from({ length: 500 }, (_, index) => ({
        ...doc.verificationMethod[0],
        id: `#key-${index}`,
      })),
    }
    const flooding = createRevocationChecker(backend, { resolver: () => oversized })
    await expect(flooding(capability, stringifyToken(capability))).rejects.toThrow(
      UnresolvableIssuerError,
    )
  })

  test('a revocation record whose issuer cannot be resolved fails closed', async () => {
    const { identity: root, resolver } = buildProfile()
    const capability = await createCapability(root, {
      sub: root.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-kokuin',
    })

    // The backend gets the registry, so the record it stores is a genuine, verified revocation.
    const backend = createMemoryRevocationBackend({ methods: [resolver] })
    await backend.add(await createRevocationRecord(root, 'cap-kokuin'))

    // The checker does not. It cannot tell whether the stored record is genuine, so it must not
    // answer "not revoked" — that would let a revoked capability verify normally.
    const checker = createRevocationChecker(backend)
    await expect(checker(capability, stringifyToken(capability))).rejects.toThrow(
      UnresolvableIssuerError,
    )
  })

  test('a revocation record with a bad signature still does not revoke', async () => {
    const { identity: root, resolver } = buildProfile()
    const capability = await createCapability(root, {
      sub: root.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-kokuin-forged',
    })

    // A genuine record, tampered. A backend that stores without verifying would hand it back.
    const genuine = await createRevocationRecord(root, 'cap-kokuin-forged')
    const forged = { ...genuine, signature: 'AAAA' }
    const untrustingBackend = {
      async add() {},
      async get() {
        return forged
      },
    }

    // The registry *is* supplied here, so the issuer resolves and the only failure left is the
    // signature. Anyone can mint such a record for any jti, so it is evidence of nothing and the
    // capability must still verify. Together with the test above this pins both failure modes:
    // an implementation that rethrew unconditionally would fail here, one that swallowed
    // everything would fail there.
    const checker = createRevocationChecker(untrustingBackend, { methods: [resolver] })
    await expect(checker(capability, stringifyToken(capability))).resolves.toBeUndefined()
  })

  test('a record naming an unrelated unresolvable issuer does not deny the capability', async () => {
    // The backend is an untrusted extension point — that is why the checker re-verifies at all —
    // so it can return a record naming any DID it likes. If the fail-closed throw were not gated
    // on the issuer matching, that record would deny *any* capability, including one issued by a
    // plain did:key with no connection to the named DID. That is a denial of service reachable
    // by design, so the gate is load-bearing.
    const madeUpDID = 'did:kokuin:zAttackerMadeThisUp' as DIDString
    const issuer = randomIdentity()
    const capability = await createCapability(issuer, {
      sub: issuer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-unrelated',
    })

    const genuine = await createRevocationRecord(issuer, 'cap-unrelated')
    const tampered = {
      ...genuine,
      payload: { ...genuine.payload, iss: madeUpDID },
      signature: 'AAAA',
    }
    // `data` must be re-derived to match the tampered header+payload. Left stale it would fail
    // verification on a data mismatch — an ordinary Error — and the record would never reach
    // issuer resolution, so the test would pass without exercising the gate at all.
    const hostile: RevocationRecord = {
      ...tampered,
      data: stringifyToken(tampered).split('.').slice(0, 2).join('.'),
    }
    const hostileBackend = {
      async add() {},
      async get() {
        return hostile
      },
    }
    const checker = createRevocationChecker(hostileBackend)

    // A record claiming some other issuer could not revoke this token even with a perfect
    // signature, so being unable to verify it costs nothing.
    await expect(checker(capability, stringifyToken(capability))).resolves.toBeUndefined()

    // Control isolating the gate: the very same unverifiable record, against a capability that
    // *does* claim the made-up DID as its issuer, must fail closed. The only difference between
    // this assertion and the one above is whether the issuers match.
    const madeUpIdentity = createSigningIdentityForDID(madeUpDID, randomPrivateKey())
    const targeted = await createCapability(madeUpIdentity, {
      sub: madeUpDID,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-unrelated',
    })
    await expect(checker(targeted, stringifyToken(targeted))).rejects.toThrow(
      UnresolvableIssuerError,
    )
  })

  test('a did:kokuin: revocation record revokes when the registry is supplied', async () => {
    const { identity: root, resolver } = buildProfile()
    const capability = await createCapability(root, {
      sub: root.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-kokuin-revoked',
    })

    const backend = createMemoryRevocationBackend({ methods: [resolver] })
    await backend.add(await createRevocationRecord(root, 'cap-kokuin-revoked'))

    const checker = createRevocationChecker(backend, { methods: [resolver] })
    await expect(checker(capability, stringifyToken(capability))).rejects.toThrow('revoked')
  })

  // A profile resolver that honours `kid` the way `@kokuin/controller`'s does: it holds one key,
  // and a `kid` naming anything else is `IssuerKeyNotFoundError` — the issuer resolved, the token
  // named a key it does not have. Hand-built for the reason `buildProfile` is: this package must
  // not depend on `@kokuin/controller`.
  const currentKid = '#zCurrentKey'

  function buildKidProfile(identity: SigningIdentity): DIDMethodResolver {
    return {
      method: 'kokuin',
      resolve: async (did: string, header: { kid?: string }) => {
        if (did !== profileDID) {
          throw new Error(`Unknown DID: ${did}`)
        }
        if (header.kid != null && header.kid !== currentKid) {
          throw new IssuerKeyNotFoundError(
            `Controller ${did} kid names a key outside the current generation: `,
          )
        }
        return { alg: 'EdDSA' as const, publicKey: identity.publicKey }
      },
      // The same answer, because this fake has one key and the record under test names a *retired*
      // one — the point of the case is that a record naming a key the profile does not have is
      // ignored, and that must hold under the historic ask a revocation check makes.
      resolveHistoric: async (did: string, header: { kid?: string }) => {
        if (did !== profileDID) {
          throw new Error(`Unknown DID: ${did}`)
        }
        if (header.kid != null && header.kid !== currentKid) {
          throw new IssuerKeyNotFoundError(
            `Controller ${did} kid names a key outside the current generation: `,
          )
        }
        return { alg: 'EdDSA' as const, publicKey: identity.publicKey }
      },
    }
  }

  test('a fabricated record with an invented kid does not deny the capability', async () => {
    const root = createSigningIdentityForDID(profileDID, randomPrivateKey())
    const resolver = buildKidProfile(root)
    const capability = await createCapability(root, {
      sub: root.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-kid-dos',
    })

    // Nothing here is signed by anyone. The backend is an untrusted extension point, so `iss` and
    // `header.kid` are both attacker-chosen, and naming the capability's own issuer is all the
    // fail-closed gate requires. If an invented `kid` made the issuer read as unresolvable, this
    // fabrication would deny every capability this profile ever issued.
    const fabricated = {
      header: { typ: 'JWT', alg: 'EdDSA', kid: '#zInventedByTheBackend' },
      payload: {
        iss: profileDID,
        jti: 'cap-kid-dos',
        rev: true,
        iat: Math.floor(Date.now() / 1000),
      },
      signature: 'AAAA',
    } as unknown as RevocationRecord
    const hostile = (record: RevocationRecord) => ({
      async add() {},
      async get() {
        return record
      },
    })

    const checker = createRevocationChecker(hostile(fabricated), { methods: [resolver] })
    await expect(checker(capability, stringifyToken(capability))).resolves.toBeUndefined()

    // Control 1: the identical fabrication *without* a `kid` is ignored too. Both halves are
    // needed — if only the second held, resolvability would still be a property of an
    // unauthenticated header field rather than of the DID.
    const noKid = { ...fabricated, header: { typ: 'JWT', alg: 'EdDSA' } } as RevocationRecord
    const noKidChecker = createRevocationChecker(hostile(noKid), { methods: [resolver] })
    await expect(noKidChecker(capability, stringifyToken(capability))).resolves.toBeUndefined()

    // Control 2: the fail-closed gate is intact. The same fabrication, against a checker with no
    // registry, still denies — the issuer genuinely cannot be resolved there.
    const blind = createRevocationChecker(hostile(fabricated))
    await expect(blind(capability, stringifyToken(capability))).rejects.toThrow(
      UnresolvableIssuerError,
    )
  })

  test('a genuine record under a retired key does not deny a capability reusing its jti', async () => {
    // The narrow version of the same defect: no forgery, just a rotation. The record is real and
    // was signed under the key of the day; the profile has since rotated, so the `kid` it stamped
    // is no longer in the key set. That is "this record is stale", not "this issuer is unknown".
    const retired = createSigningIdentityForDID(profileDID, randomPrivateKey())
    const current = createSigningIdentityForDID(profileDID, randomPrivateKey())
    const resolver = buildKidProfile(current)
    const iat = Math.floor(Date.now() / 1000)

    const capability = await createCapability(current, {
      sub: profileDID,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-reused-jti',
    })
    const stale = (await retired.signToken(
      { jti: 'cap-reused-jti', rev: true, iat },
      { header: { kid: '#zRetiredKey' } },
    )) as RevocationRecord

    const checker = createRevocationChecker(
      {
        async add() {},
        async get() {
          return stale
        },
      },
      { methods: [resolver] },
    )
    await expect(checker(capability, stringifyToken(capability))).resolves.toBeUndefined()

    // Control: a record naming the *current* key over the same jti still revokes, so the pass
    // above is the retired `kid` being ignored and not the checker having stopped working.
    const live = (await current.signToken(
      { jti: 'cap-reused-jti', rev: true, iat },
      { header: { kid: currentKid } },
    )) as RevocationRecord
    const liveChecker = createRevocationChecker(
      {
        async add() {},
        async get() {
          return live
        },
      },
      { methods: [resolver] },
    )
    await expect(liveChecker(capability, stringifyToken(capability))).rejects.toThrow('revoked')
  })
})
