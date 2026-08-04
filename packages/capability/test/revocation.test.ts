import { createIdentity, randomIdentity, stringifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { checkDelegationChain, createCapability } from '../src/index.js'
import {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
} from '../src/revocation.js'

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
})
