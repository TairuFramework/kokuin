import {
  createIdentity,
  createInMemoryDIDCache,
  createSigningIdentityForDID,
  type DIDMethodResolver,
  type DIDResolver,
  type DIDString,
  decodePeer4,
  randomIdentity,
  randomPrivateKey,
  stringifyToken,
  verifyToken,
} from '@kokuin/token'
import { describe, expect, test, vi } from 'vitest'

import {
  assertCapabilityToken,
  assertNonExpired,
  assertValidDelegation,
  assertValidIssuedAt,
  assertValidPattern,
  type CapabilityPayload,
  checkCapability,
  checkDelegationChain,
  createCapability,
  hasPermission,
  isCapabilityToken,
  now,
} from '../src/index.js'

describe('hasPermission()', () => {
  test('with single action and resource', () => {
    // Same action, different resources
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/read', res: 'foo/bar' }),
    ).toBe(true)
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/read', res: 'foo/baz' }),
    ).toBe(false)
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/read', res: 'foo/*' }),
    ).toBe(true)
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/read', res: '*' }),
    ).toBe(true)
    expect(hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/read', res: '' })).toBe(
      false,
    )
    // Same resource, different actions
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/read', res: 'foo/bar' }),
    ).toBe(true)

    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/write', res: 'foo/bar' }),
    ).toBe(false)
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/*', res: 'foo/bar' }),
    ).toBe(true)
    expect(hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: '*', res: 'foo/bar' })).toBe(
      true,
    )
    expect(hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: '', res: 'foo/bar' })).toBe(
      false,
    )
  })

  test('with multiple actions or resources granted, check for any match', () => {
    // Same action, different resources
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: 'test/read', res: ['foo/foo', 'foo/baz'] },
      ),
    ).toBe(false)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: 'test/read', res: ['foo/foo', 'foo/*'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: 'test/read', res: ['foo/foo', '*'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: 'test/read', res: ['foo/foo', ''] },
      ),
    ).toBe(false)
    // Same resource, different actions
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: ['test/other', 'test/read'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: ['test/other', 'test/write'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(false)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: ['test/other', 'test/*'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: ['test/other', '*'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar' },
        { act: ['test/other', ''], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(false)
  })

  test('with multiple actions or resources expected, check for every match', () => {
    // Same action, different resources
    expect(
      hasPermission(
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        { act: 'test/read', res: ['foo/foo', 'foo/baz'] },
      ),
    ).toBe(false)
    expect(
      hasPermission(
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        { act: 'test/read', res: ['foo/foo', 'foo/*'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        { act: 'test/read', res: ['foo/foo', ''] },
      ),
    ).toBe(false)
    expect(
      hasPermission(
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        { act: 'test/read', res: 'foo/*' },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        { act: 'test/read', res: '*' },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        { act: 'test/read', res: '' },
      ),
    ).toBe(false)
    // Same resource, different actions
    expect(
      hasPermission(
        { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: ['test/read', 'test/delete'], res: ['foo/foo', 'foo/bar'] },
        { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(false)
    expect(
      hasPermission(
        { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        { act: ['test/read'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(false)
    expect(
      hasPermission(
        { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        { act: ['test/read', 'test/*'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        { act: ['test/read', '*'], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(true)
    expect(
      hasPermission(
        { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        { act: ['test/read', ''], res: ['foo/foo', 'foo/bar'] },
      ),
    ).toBe(false)
  })

  test('does not grant ancestor resources or actions (prefix escalation)', () => {
    // A grant more specific than the request must NOT authorize the broader request.
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar' }, { act: 'test/read', res: 'foo/bar/baz' }),
    ).toBe(false)
    expect(
      hasPermission({ act: 'test/read', res: 'foo' }, { act: 'test/read', res: 'foo/bar/baz' }),
    ).toBe(false)
    expect(
      hasPermission({ act: 'test', res: 'foo/bar' }, { act: 'test/read', res: 'foo/bar' }),
    ).toBe(false)

    // No implicit descent: a shorter grant does not cover a deeper request without `*`.
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar/baz' }, { act: 'test/read', res: 'foo/bar' }),
    ).toBe(false)
    expect(
      hasPermission(
        { act: 'test/read/extra', res: 'foo/bar' },
        { act: 'test/read', res: 'foo/bar' },
      ),
    ).toBe(false)

    // Explicit trailing `*` is still required to authorize deeper requests.
    expect(
      hasPermission({ act: 'test/read', res: 'foo/bar/baz' }, { act: 'test/read', res: 'foo/*' }),
    ).toBe(true)
    expect(
      hasPermission(
        { act: 'test/read', res: 'foo/bar/baz' },
        { act: 'test/read', res: 'foo/bar/*' },
      ),
    ).toBe(true)
  })
})

describe('assertNonExpired()', () => {
  test('with no expiration', () => {
    expect(() => assertNonExpired({})).not.toThrow()
    expect(() => assertNonExpired({ exp: undefined })).not.toThrow()
  })

  test('with valid expiration', () => {
    const exp = now() + 1000
    expect(() => assertNonExpired({ exp })).not.toThrow()
    expect(() => assertNonExpired({ exp }, exp - 100)).not.toThrow()
  })

  test('with invalid expiration', () => {
    const exp = now() - 1000
    expect(() => assertNonExpired({ exp })).toThrow('Invalid token: expired')
    expect(() => assertNonExpired({ exp: exp - 1000 }, exp)).toThrow('Invalid token: expired')
  })
})

describe('assertValidIssuedAt()', () => {
  test('accepts payload without iat', () => {
    expect(() => assertValidIssuedAt({})).not.toThrow()
    expect(() => assertValidIssuedAt({ iat: undefined })).not.toThrow()
  })

  test('accepts payload with past iat', () => {
    const iat = now() - 1000
    expect(() => assertValidIssuedAt({ iat })).not.toThrow()
  })

  test('accepts payload with current iat', () => {
    const iat = now()
    expect(() => assertValidIssuedAt({ iat })).not.toThrow()
  })

  test('rejects payload with future iat', () => {
    const iat = now() + 1000
    expect(() => assertValidIssuedAt({ iat })).toThrow('Invalid token: issued in the future')
  })

  test('respects atTime parameter', () => {
    const fixedTime = 1700000000
    // iat is before atTime — OK
    expect(() => assertValidIssuedAt({ iat: fixedTime - 100 }, fixedTime)).not.toThrow()
    // iat is after atTime — rejected
    expect(() => assertValidIssuedAt({ iat: fixedTime + 100 }, fixedTime)).toThrow(
      'Invalid token: issued in the future',
    )
  })
})

describe('assertValidDelegation()', () => {
  test('checks matching issuer and audience', () => {
    expect(() => {
      assertValidDelegation(
        { aud: 'did:test:123' } as CapabilityPayload,
        { iss: 'did:test:123' } as CapabilityPayload,
      )
    }).not.toThrow()
    expect(() => {
      assertValidDelegation(
        { aud: 'did:test:456' } as CapabilityPayload,
        { iss: 'did:test:123' } as CapabilityPayload,
      )
    }).toThrow('Invalid capability: audience mismatch')
  })

  test('checks matching subject', () => {
    expect(() => {
      assertValidDelegation(
        { aud: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
        { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
      )
    }).not.toThrow()
    expect(() => {
      assertValidDelegation(
        { aud: 'did:test:123', sub: 'did:test:789' } as CapabilityPayload,
        { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
      )
    }).toThrow('Invalid capability: subject mismatch')
  })

  test('checks expired parent', () => {
    expect(() => {
      assertValidDelegation(
        { aud: 'did:test:123', sub: 'did:test:456', exp: now() + 1000 } as CapabilityPayload,
        { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
      )
    }).not.toThrow()
    expect(() => {
      assertValidDelegation(
        { aud: 'did:test:123', sub: 'did:test:456', exp: now() - 1000 } as CapabilityPayload,
        { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
      )
    }).toThrow('Invalid token: expired')
  })

  test('checks matching actions and resources', () => {
    expect(() => {
      assertValidDelegation(
        {
          aud: 'did:test:123',
          sub: 'did:test:456',
          act: 'test',
          res: 'foo/*',
        } as CapabilityPayload,
        {
          iss: 'did:test:123',
          sub: 'did:test:456',
          act: 'test',
          res: ['foo/bar', 'foo/baz'],
        } as CapabilityPayload,
      )
    }).not.toThrow()
    expect(() => {
      assertValidDelegation(
        {
          aud: 'did:test:123',
          sub: 'did:test:456',
          act: 'test',
          res: ['foo/bar', 'foo/foo'],
        } as CapabilityPayload,
        {
          iss: 'did:test:123',
          sub: 'did:test:456',
          act: 'test',
          res: ['foo/bar', 'foo/baz'],
        } as CapabilityPayload,
      )
    }).toThrow('Invalid capability: permission mismatch')
  })
})

describe('checkDelegationChain()', () => {
  test('last payload should be issued by subject and not expired', async () => {
    await expect(
      checkDelegationChain({ iss: 'did:test:123', sub: 'did:test:123' } as CapabilityPayload, []),
    ).resolves.toBeUndefined()
    await expect(async () => {
      await checkDelegationChain(
        { iss: 'did:test:123', sub: 'did:test:123', exp: now() - 1000 } as CapabilityPayload,
        [],
      )
    }).rejects.toThrow('Invalid token: expired')
    await expect(async () => {
      await checkDelegationChain(
        { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
        [],
      )
    }).rejects.toThrow('Invalid capability: issuer should be subject')
  })

  test('validates the full chain', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()
    const signerC = randomIdentity()
    const signerD = randomIdentity()
    const delegateToB = await createCapability(signerA, {
      sub: signerA.id,
      aud: signerB.id,
      act: '*',
      res: 'foo/*',
    })
    const delegateToC = await createCapability(
      signerB,
      {
        sub: signerA.id,
        aud: signerC.id,
        act: 'test/*',
        res: ['foo/bar', 'foo/baz'],
      },
      undefined,
      { parentCapability: stringifyToken(delegateToB) },
    )
    const delegateToD = await createCapability(
      signerC,
      {
        sub: signerA.id,
        aud: signerD.id,
        act: ['test/read', 'test/write'],
        res: 'foo/baz',
      },
      undefined,
      { parentCapability: stringifyToken(delegateToC) },
    )
    await expect(
      checkDelegationChain(delegateToD.payload, [
        stringifyToken(delegateToC),
        stringifyToken(delegateToB),
      ]),
    ).resolves.not.toThrow()
  })
})

describe('checkCapability()', () => {
  test('validates the full chain', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()
    const signerC = randomIdentity()
    const signerD = randomIdentity()
    const delegateToB = await createCapability(signerA, {
      sub: signerA.id,
      aud: signerB.id,
      act: '*',
      res: ['foo/*'],
    })
    const delegateToC = await createCapability(
      signerB,
      {
        sub: signerA.id,
        aud: signerC.id,
        act: 'test/*',
        res: ['foo/bar', 'foo/baz'],
      },
      undefined,
      { parentCapability: stringifyToken(delegateToB) },
    )
    const delegateToD = await createCapability(
      signerC,
      {
        sub: signerA.id,
        aud: signerD.id,
        act: 'test/*',
        res: ['foo/baz'],
      },
      undefined,
      { parentCapability: stringifyToken(delegateToC) },
    )
    const token = await signerD.signToken({
      sub: signerA.id,
      prc: 'test/call',
      cap: [stringifyToken(delegateToD), stringifyToken(delegateToC), stringifyToken(delegateToB)],
    })
    await expect(
      checkCapability({ act: 'test/call', res: 'foo/baz' }, token.payload),
    ).resolves.not.toThrow()
  })

  test('rejects expired capability token', async () => {
    const fixedTime = 1700000000
    const alice = randomIdentity()
    const bob = randomIdentity()

    // Create an expired capability
    const capability = await createCapability(alice, {
      sub: alice.id,
      aud: bob.id,
      act: 'test/read',
      res: 'foo/bar',
      exp: fixedTime - 100, // Expired
    })

    const bobToken = await bob.signToken({
      sub: alice.id,
      act: 'test/read',
      res: 'foo/bar',
      cap: stringifyToken(capability),
    })

    await expect(
      checkCapability({ act: 'test/read', res: 'foo/bar' }, bobToken.payload, {
        atTime: fixedTime,
      }),
    ).rejects.toThrow('Token expired')
  })

  test('honors atTime for the leaf capability — valid-when-issued passes despite later expiry', async () => {
    // exp is in the real past, so a wall-clock (now()) verification would reject
    // the leaf capability outright. atTime is before exp, so the capability was
    // valid at the reference time and must be accepted.
    const referenceTime = 1700000000
    const alice = randomIdentity()
    const bob = randomIdentity()

    const capability = await createCapability(alice, {
      sub: alice.id,
      aud: bob.id,
      act: 'test/read',
      res: 'foo/bar',
      exp: referenceTime + 100,
    })

    const bobToken = await bob.signToken({
      sub: alice.id,
      act: 'test/read',
      res: 'foo/bar',
      cap: stringifyToken(capability),
    })

    await expect(
      checkCapability({ act: 'test/read', res: 'foo/bar' }, bobToken.payload, {
        atTime: referenceTime,
      }),
    ).resolves.not.toThrow()
  })
})

describe('checkCapability() - self-issued tokens (C-02)', () => {
  test('validates permissions even for self-issued tokens', async () => {
    const alice = randomIdentity()

    // Alice creates a self-issued token claiming only 'read' permission
    const token = await alice.signToken({
      sub: alice.id,
      act: 'test/read',
      res: 'foo/bar',
    })

    // Should succeed: requesting exactly what was granted
    await expect(
      checkCapability({ act: 'test/read', res: 'foo/bar' }, token.payload),
    ).resolves.not.toThrow()

    // Should FAIL: requesting 'write' when only 'read' was granted
    // BUG: Currently passes because iss === sub bypasses permission check
    await expect(
      checkCapability({ act: 'test/write', res: 'foo/bar' }, token.payload),
    ).rejects.toThrow()
  })

  test('validates resource even for self-issued tokens', async () => {
    const alice = randomIdentity()

    const token = await alice.signToken({
      sub: alice.id,
      act: 'test/read',
      res: 'foo/bar',
    })

    // Should FAIL: requesting different resource
    await expect(
      checkCapability({ act: 'test/read', res: 'foo/baz' }, token.payload),
    ).rejects.toThrow()
  })

  test('respects wildcard permissions for self-issued tokens', async () => {
    const alice = randomIdentity()

    const token = await alice.signToken({
      sub: alice.id,
      act: '*',
      res: 'foo/*',
    })

    // Should succeed: wildcard covers this
    await expect(
      checkCapability({ act: 'test/read', res: 'foo/bar' }, token.payload),
    ).resolves.not.toThrow()

    // Should fail: resource doesn't match wildcard
    await expect(
      checkCapability({ act: 'test/read', res: 'bar/baz' }, token.payload),
    ).rejects.toThrow()
  })

  test('requires act and res claims for self-issued tokens', async () => {
    const alice = randomIdentity()

    // Token without act/res claims
    const token = await alice.signToken({
      sub: alice.id,
    })

    await expect(
      checkCapability({ act: 'test/read', res: 'foo/bar' }, token.payload),
    ).rejects.toThrow()
  })
})

describe('checkDelegationChain() - depth limits (H-04)', () => {
  async function buildDelegationChain(signers: Array<ReturnType<typeof randomIdentity>>) {
    const capabilities: Array<string> = []
    for (let i = 0; i < signers.length - 1; i++) {
      const parentOption = i > 0 ? { parentCapability: capabilities[i - 1] } : undefined
      const cap = await createCapability(
        signers[i],
        {
          sub: signers[0].id,
          aud: signers[i + 1].id,
          act: '*',
          res: '*',
        },
        undefined,
        parentOption,
      )
      capabilities.push(stringifyToken(cap))
    }
    return capabilities
  }

  test('rejects delegation chains exceeding max depth', async () => {
    const signers = Array.from({ length: 25 }, () => randomIdentity())

    // Build a chain of 24 delegations (exceeds default limit of 20)
    const capabilities = await buildDelegationChain(signers)

    const finalPayload = {
      iss: signers[signers.length - 1].id,
      sub: signers[0].id,
      act: 'test',
      res: 'foo',
    } as CapabilityPayload

    // Should reject: chain depth exceeds limit
    await expect(checkDelegationChain(finalPayload, [...capabilities].reverse())).rejects.toThrow(
      'delegation chain exceeds maximum depth',
    )
  })

  test('accepts delegation chains within max depth', async () => {
    const signers = Array.from({ length: 5 }, () => randomIdentity())

    const capabilities = await buildDelegationChain(signers)

    const finalPayload = {
      iss: signers[signers.length - 1].id,
      sub: signers[0].id,
      act: 'test',
      res: 'foo',
    } as CapabilityPayload

    // Should succeed: chain depth within limit
    await expect(
      checkDelegationChain(finalPayload, [...capabilities].reverse()),
    ).resolves.not.toThrow()
  })

  test('respects custom maxDepth option', async () => {
    const signers = Array.from({ length: 5 }, () => randomIdentity())

    const capabilities = await buildDelegationChain(signers)

    const finalPayload = {
      iss: signers[signers.length - 1].id,
      sub: signers[0].id,
      act: 'test',
      res: 'foo',
    } as CapabilityPayload

    const reversed = [...capabilities].reverse()

    // Should reject: custom limit of 2
    await expect(checkDelegationChain(finalPayload, reversed, { maxDepth: 2 })).rejects.toThrow(
      'delegation chain exceeds maximum depth',
    )

    // Should succeed: custom limit of 10
    await expect(
      checkDelegationChain(finalPayload, reversed, { maxDepth: 10 }),
    ).resolves.not.toThrow()
  })
})

describe('isCapabilityToken() - type validation (M-04)', () => {
  const identity = randomIdentity()

  // Signs a canonical capability payload, brands it via verifyToken, then
  // mutates the payload in-place so the WeakSet brand (keyed on object
  // identity) survives the override.
  async function makeToken(payload: Record<string, unknown>) {
    const signed = await identity.signToken({
      sub: identity.id,
      aud: 'did:test:789',
      act: 'test',
      res: 'foo',
    } as Record<string, unknown>)
    const branded = await verifyToken(signed)
    Object.assign(branded.payload, payload)
    return branded
  }

  test('rejects token with non-string iss', async () => {
    // Note: isSignedToken (called by isVerifiedToken) also validates iss as a
    // string, so this case is caught at the isSignedToken layer rather than
    // isCapabilityToken's own check. The result is still false.
    const token = await makeToken({
      iss: 123, // Override default string iss
      sub: 'did:test:456',
      aud: 'did:test:789',
      act: 'test',
      res: 'foo',
    })
    expect(isCapabilityToken(token)).toBe(false)
  })

  test('rejects token with non-string aud', async () => {
    // Note: isSignedToken also validates aud as a string when present, so this
    // case is caught at the isSignedToken layer. Result is still false.
    const token = await makeToken({
      sub: 'did:test:456',
      aud: 123, // Should be string
      act: 'test',
      res: 'foo',
    })
    expect(isCapabilityToken(token)).toBe(false)
  })

  test('rejects token with non-string sub', async () => {
    // Note: isSignedToken also validates sub as a string when present, so this
    // case is caught at the isSignedToken layer. Result is still false.
    const token = await makeToken({
      sub: { id: '456' }, // Should be string
      aud: 'did:test:789',
      act: 'test',
      res: 'foo',
    })
    expect(isCapabilityToken(token)).toBe(false)
  })

  test('rejects token with invalid act type', async () => {
    const token = await makeToken({
      sub: 'did:test:456',
      aud: 'did:test:789',
      act: 123, // Should be string or string[]
      res: 'foo',
    })
    expect(isCapabilityToken(token)).toBe(false)
  })

  test('rejects token with invalid res type', async () => {
    const token = await makeToken({
      sub: 'did:test:456',
      aud: 'did:test:789',
      act: 'test',
      res: { path: 'foo' }, // Should be string or string[]
    })
    expect(isCapabilityToken(token)).toBe(false)
  })

  test('accepts token with string act and res', async () => {
    const token = await makeToken({
      sub: 'did:test:456',
      aud: 'did:test:789',
      act: 'test',
      res: 'foo',
    })
    expect(isCapabilityToken(token)).toBe(true)
  })

  test('accepts token with array act and res', async () => {
    const token = await makeToken({
      sub: 'did:test:456',
      aud: 'did:test:789',
      act: ['read', 'write'],
      res: ['foo', 'bar'],
    })
    expect(isCapabilityToken(token)).toBe(true)
  })

  test('rejects token with mixed array containing non-strings', async () => {
    const token = await makeToken({
      sub: 'did:test:456',
      aud: 'did:test:789',
      act: ['read', 123], // Invalid: number in array
      res: 'foo',
    })
    expect(isCapabilityToken(token)).toBe(false)
  })
})

describe('TOCTOU time consistency (M-05)', () => {
  test('assertValidDelegation uses consistent time for expiration and iat checks', () => {
    const fixedTime = 1700000000
    const from = {
      iss: 'did:test:a',
      aud: 'did:test:b',
      sub: 'did:test:a',
      act: '*',
      res: '*',
      exp: fixedTime + 100,
      iat: fixedTime - 100,
    } as CapabilityPayload
    const to = {
      iss: 'did:test:b',
      sub: 'did:test:a',
      act: 'test',
      res: 'foo',
    } as CapabilityPayload

    // Should pass with explicit atTime
    expect(() => assertValidDelegation(from, to, fixedTime)).not.toThrow()
  })

  test('checkDelegationChain captures time once when atTime not provided', async () => {
    const signer = randomIdentity()
    const payload = {
      iss: signer.id,
      sub: signer.id,
      act: 'test',
      res: 'foo',
      iat: now() - 10,
    } as CapabilityPayload

    // Should pass: iat is in the past, no expiration
    await expect(checkDelegationChain(payload, [])).resolves.not.toThrow()
  })
})

describe('assertValidPattern() (M-06)', () => {
  test('accepts simple patterns', () => {
    expect(() => assertValidPattern('test')).not.toThrow()
    expect(() => assertValidPattern('test/read')).not.toThrow()
    expect(() => assertValidPattern('foo/bar/baz')).not.toThrow()
  })

  test('accepts wildcard patterns', () => {
    expect(() => assertValidPattern('*')).not.toThrow()
    expect(() => assertValidPattern('test/*')).not.toThrow()
    expect(() => assertValidPattern('foo/bar/*')).not.toThrow()
  })

  test('accepts patterns with hyphens, underscores, dots, colons', () => {
    expect(() => assertValidPattern('my-action')).not.toThrow()
    expect(() => assertValidPattern('my_resource')).not.toThrow()
    expect(() => assertValidPattern('v1.0/api')).not.toThrow()
    expect(() => assertValidPattern('ns:action')).not.toThrow()
  })

  test('rejects empty string', () => {
    expect(() => assertValidPattern('')).toThrow('Invalid pattern')
  })

  test('rejects path traversal', () => {
    expect(() => assertValidPattern('../admin')).toThrow('Invalid pattern')
    expect(() => assertValidPattern('foo/../bar')).toThrow('Invalid pattern')
    expect(() => assertValidPattern('./hidden')).toThrow('Invalid pattern')
  })

  test('rejects null bytes and control characters', () => {
    expect(() => assertValidPattern('foo\x00bar')).toThrow('Invalid pattern')
    expect(() => assertValidPattern('foo\nbar')).toThrow('Invalid pattern')
    expect(() => assertValidPattern('foo\rbar')).toThrow('Invalid pattern')
  })

  test('rejects double slashes', () => {
    expect(() => assertValidPattern('foo//bar')).toThrow('Invalid pattern')
  })

  test('rejects leading or trailing slashes', () => {
    expect(() => assertValidPattern('/foo')).toThrow('Invalid pattern')
    expect(() => assertValidPattern('foo/')).toThrow('Invalid pattern')
  })

  test('rejects misplaced wildcards', () => {
    expect(() => assertValidPattern('*/foo')).toThrow('Invalid pattern')
    expect(() => assertValidPattern('foo/*/bar')).toThrow('Invalid pattern')
    expect(() => assertValidPattern('foo*')).toThrow('Invalid pattern')
    expect(() => assertValidPattern('*bar')).toThrow('Invalid pattern')
  })

  test('validates arrays', () => {
    expect(() => assertValidPattern(['test/read', 'test/write'])).not.toThrow()
    expect(() => assertValidPattern(['test/read', '../bad'])).toThrow('Invalid pattern')
  })
})

describe('createCapability() - delegation validation (C-03)', () => {
  test('creates capability when signer is the subject (root capability)', async () => {
    const alice = randomIdentity()

    // Alice creates a capability for herself - always allowed
    const cap = await createCapability(alice, {
      sub: alice.id,
      aud: 'did:test:bob',
      act: 'test/read',
      res: 'foo/bar',
    })

    expect(cap.payload.iss).toBe(alice.id)
    expect(cap.payload.sub).toBe(alice.id)
  })

  test('creates capability with parent validation when delegating', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    // Alice creates root capability for Bob
    const rootCap = await createCapability(alice, {
      sub: alice.id,
      aud: bob.id,
      act: '*',
      res: 'foo/*',
    })

    // Bob can delegate to Carol with valid parent
    const carol = randomIdentity()
    const delegatedCap = await createCapability(
      bob,
      {
        sub: alice.id,
        aud: carol.id,
        act: 'test/read',
        res: 'foo/bar',
      },
      undefined,
      { parentCapability: stringifyToken(rootCap) },
    )

    expect(delegatedCap.payload.iss).toBe(bob.id)
    expect(delegatedCap.payload.sub).toBe(alice.id)
  })

  test('rejects delegation that exceeds parent permissions', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    const rootCap = await createCapability(alice, {
      sub: alice.id,
      aud: bob.id,
      act: 'test/read', // Only read
      res: 'foo/bar',
    })

    const carol = randomIdentity()

    // Bob tries to delegate 'write' which he doesn't have
    await expect(
      createCapability(
        bob,
        {
          sub: alice.id,
          aud: carol.id,
          act: 'test/write', // Exceeds parent
          res: 'foo/bar',
        },
        undefined,
        { parentCapability: stringifyToken(rootCap) },
      ),
    ).rejects.toThrow('permission')
  })

  test('rejects delegation without parentCapability when signer is not subject', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    // Bob tries to delegate for Alice without providing a parent capability
    await expect(
      createCapability(bob, {
        sub: alice.id,
        aud: 'did:test:carol',
        act: 'test/read',
        res: 'foo/bar',
      }),
    ).rejects.toThrow('parentCapability required')
  })

  test('rejects delegation when signer is not the parent audience', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()
    const eve = randomIdentity() // Attacker

    const rootCap = await createCapability(alice, {
      sub: alice.id,
      aud: bob.id,
      act: '*',
      res: '*',
    })

    // Eve tries to use Bob's capability
    await expect(
      createCapability(
        eve,
        {
          sub: alice.id,
          aud: 'did:test:victim',
          act: '*',
          res: '*',
        },
        undefined,
        { parentCapability: stringifyToken(rootCap) },
      ),
    ).rejects.toThrow('audience')
  })

  test('delegates from a did:kokuin: root when methods is provided, and fails without it', async () => {
    // A DID whose keys cannot be recovered from the identifier -- the shape `did:kokuin:` has.
    // The resolver here is a hand-built fake: this package must not depend on
    // `@kokuin/controller`, and a real folded log would prove nothing extra about the option
    // threading. Mirrors the idiom in `test/method-registry.test.ts`.
    const profileDID = 'did:kokuin:zTestProfile' as DIDString
    const root = createSigningIdentityForDID(profileDID, randomPrivateKey())
    const resolver: DIDMethodResolver = {
      method: 'kokuin',
      resolve: async (did: string) => {
        if (did !== profileDID) {
          throw new Error(`Unknown DID: ${did}`)
        }
        return { alg: 'EdDSA', publicKey: root.publicKey }
      },
    }
    const bob = randomIdentity()
    const carol = randomIdentity()

    const rootCap = await createCapability(root, {
      sub: profileDID,
      aud: bob.id,
      act: '*',
      res: 'foo/*',
    })

    const delegated = await createCapability(
      bob,
      {
        sub: profileDID,
        aud: carol.id,
        act: 'test/read',
        res: 'foo/bar',
      },
      undefined,
      { parentCapability: stringifyToken(rootCap), methods: [resolver] },
    )
    expect(delegated.payload.iss).toBe(bob.id)
    expect(delegated.payload.sub).toBe(profileDID)

    // Without the registry, the did:kokuin: parent capability cannot be verified at all -- an
    // implementation that ignores `methods` here would pass the assertion above but not this one.
    await expect(
      createCapability(
        bob,
        {
          sub: profileDID,
          aud: carol.id,
          act: 'test/read',
          res: 'foo/bar',
        },
        undefined,
        { parentCapability: stringifyToken(rootCap) },
      ),
    ).rejects.toThrow(`Unknown DID: ${profileDID}`)
  })

  test('delegates from a did:peer:4 short-form root when cache is provided, and fails without it', async () => {
    // The same resolution gap `methods` closes for did:kokuin: exists for a did:peer:4 short
    // form the verifier has not seen yet -- `cache` and `resolver` travel with `methods` on
    // `CreateCapabilityOptions` for that reason.
    const alice = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const bob = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const carol = randomIdentity()

    // Alice signs with her short form: without a cache entry or resolver, nothing can turn that
    // short form back into her signing key.
    const rootCap = await alice.signToken(
      { sub: alice.id, aud: bob.id, act: '*', res: 'foo/*' },
      { embedLongForm: false },
    )
    const cache = createInMemoryDIDCache()
    await cache.set(alice.id, alice.doc)

    // Note: no `resolver` anywhere in this test -- this isolates `cache` from `resolver`, so a
    // future implementation that forwards `resolver` but not `cache` cannot pass this test by
    // accident.
    const delegated = await createCapability(
      bob,
      { sub: alice.id, aud: carol.id, act: 'test/read', res: 'foo/bar' },
      undefined,
      { parentCapability: stringifyToken(rootCap), cache },
    )
    // First contact with carol: bob's own signer embeds his long form, unrelated to the option
    // under test.
    expect(delegated.payload.iss).toBe(bob.longForm)
    expect(delegated.payload.sub).toBe(alice.id)

    // Without the cache, an implementation that ignores it here would pass the assertion above
    // but not this one.
    await expect(
      createCapability(
        bob,
        { sub: alice.id, aud: carol.id, act: 'test/read', res: 'foo/bar' },
        undefined,
        { parentCapability: stringifyToken(rootCap) },
      ),
    ).rejects.toThrow(`Unknown DID: ${alice.id}`)
  })

  test('delegates from a did:peer:4 short-form root when resolver is provided, and fails without it', async () => {
    // Isolates `resolver` from `cache`: no `cache` anywhere in this test, on either call, so a
    // resolver-only path is the only way the short-form root capability's issuer can resolve.
    // Models the sibling resolver-only case in `test/revocation.test.ts` (Task 26).
    const alice = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const bob = randomIdentity()
    const carol = randomIdentity()

    // Alice signs with her short form: without a resolver (or a cache entry), nothing can turn
    // that short form back into her signing key.
    const rootCap = await alice.signToken(
      { sub: alice.id, aud: bob.id, act: '*', res: 'foo/*' },
      { embedLongForm: false },
    )
    const doc = decodePeer4(alice.longForm).doc
    const resolver: DIDResolver = (did: string) => (did === alice.id ? doc : undefined)

    const delegated = await createCapability(
      bob,
      { sub: alice.id, aud: carol.id, act: 'test/read', res: 'foo/bar' },
      undefined,
      { parentCapability: stringifyToken(rootCap), resolver },
    )
    expect(delegated.payload.iss).toBe(bob.id)
    expect(delegated.payload.sub).toBe(alice.id)

    // Without the resolver, an implementation that ignores it here would pass the assertion
    // above but not this one.
    await expect(
      createCapability(
        bob,
        { sub: alice.id, aud: carol.id, act: 'test/read', res: 'foo/bar' },
        undefined,
        { parentCapability: stringifyToken(rootCap) },
      ),
    ).rejects.toThrow(`Unknown DID: ${alice.id}`)
  })
})

describe('verifyToken hook', () => {
  test('checkDelegationChain calls verifyToken for each token in the chain', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()
    const signerC = randomIdentity()

    const delegateToB = await createCapability(signerA, {
      sub: signerA.id,
      aud: signerB.id,
      act: '*',
      res: '*',
    })
    const delegateToC = await createCapability(
      signerB,
      {
        sub: signerA.id,
        aud: signerC.id,
        act: 'test/*',
        res: 'foo/*',
      },
      undefined,
      { parentCapability: stringifyToken(delegateToB) },
    )

    const verified: Array<string> = []
    const verifyToken = vi.fn((_token: unknown, raw: string) => {
      verified.push(raw)
    })

    await checkDelegationChain(delegateToC.payload, [stringifyToken(delegateToB)], { verifyToken })

    expect(verifyToken).toHaveBeenCalledTimes(1)
    expect(verified[0]).toBe(stringifyToken(delegateToB))
  })

  test('checkDelegationChain rejects when verifyToken throws', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()

    const delegateToB = await createCapability(signerA, {
      sub: signerA.id,
      aud: signerB.id,
      act: '*',
      res: '*',
    })

    const verifyToken = vi.fn(() => {
      throw new Error('Token revoked')
    })

    await expect(
      checkDelegationChain(delegateToB.payload, [stringifyToken(delegateToB)], { verifyToken }),
    ).rejects.toThrow('Token revoked')
  })

  test('checkCapability calls verifyToken for capability tokens', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    const capability = await createCapability(alice, {
      sub: alice.id,
      aud: bob.id,
      act: 'test/read',
      res: 'foo/bar',
    })

    const capString = stringifyToken(capability)
    const token = await bob.signToken({
      sub: alice.id,
      prc: 'test/read',
      cap: capString,
    })

    const verifyTokenHook = vi.fn()

    await checkCapability({ act: 'test/read', res: 'foo/bar' }, token.payload, {
      verifyToken: verifyTokenHook,
    })

    expect(verifyTokenHook).toHaveBeenCalledTimes(1)
    expect(verifyTokenHook).toHaveBeenCalledWith(
      expect.objectContaining({
        payload: expect.objectContaining({ iss: alice.id, aud: bob.id }),
      }),
      capString,
    )
  })

  test('checkCapability rejects when verifyToken throws for capability', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    const capability = await createCapability(alice, {
      sub: alice.id,
      aud: bob.id,
      act: 'test/read',
      res: 'foo/bar',
    })

    const token = await bob.signToken({
      sub: alice.id,
      prc: 'test/read',
      cap: stringifyToken(capability),
    })

    const verifyTokenHook = vi.fn(() => {
      throw new Error('Token revoked')
    })

    await expect(
      checkCapability({ act: 'test/read', res: 'foo/bar' }, token.payload, {
        verifyToken: verifyTokenHook,
      }),
    ).rejects.toThrow('Token revoked')
  })

  test('checkCapability does not call verifyToken for self-issued tokens', async () => {
    const alice = randomIdentity()

    const token = await alice.signToken({
      sub: alice.id,
      act: 'test/read',
      res: 'foo/bar',
    })

    const verifyTokenHook = vi.fn()

    await checkCapability({ act: 'test/read', res: 'foo/bar' }, token.payload, {
      verifyToken: verifyTokenHook,
    })

    expect(verifyTokenHook).not.toHaveBeenCalled()
  })

  test('checkCapability calls verifyToken for full delegation chain', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()
    const signerC = randomIdentity()

    const delegateToB = await createCapability(signerA, {
      sub: signerA.id,
      aud: signerB.id,
      act: '*',
      res: 'foo/*',
    })
    const delegateToC = await createCapability(
      signerB,
      {
        sub: signerA.id,
        aud: signerC.id,
        act: 'test/*',
        res: 'foo/bar',
      },
      undefined,
      { parentCapability: stringifyToken(delegateToB) },
    )

    const token = await signerC.signToken({
      sub: signerA.id,
      prc: 'test/call',
      cap: [stringifyToken(delegateToC), stringifyToken(delegateToB)],
    })

    const verifyTokenHook = vi.fn()

    await checkCapability({ act: 'test/call', res: 'foo/bar' }, token.payload, {
      verifyToken: verifyTokenHook,
    })

    // Should be called for both tokens in the chain
    expect(verifyTokenHook).toHaveBeenCalledTimes(2)
  })

  test('checkCapability supports async verifyToken', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    const capability = await createCapability(alice, {
      sub: alice.id,
      aud: bob.id,
      act: 'test/read',
      res: 'foo/bar',
    })

    const token = await bob.signToken({
      sub: alice.id,
      prc: 'test/read',
      cap: stringifyToken(capability),
    })

    const verifyTokenHook = vi.fn(async () => {
      // Simulate async revocation check
      await new Promise((resolve) => setTimeout(resolve, 1))
    })

    await checkCapability({ act: 'test/read', res: 'foo/bar' }, token.payload, {
      verifyToken: verifyTokenHook,
    })

    expect(verifyTokenHook).toHaveBeenCalledTimes(1)
  })
})

describe('checkCapability() - a capability presented directly rather than invoked', () => {
  // The shape `createControllerCapabilityVerifier` hands over: a key event names a capability and
  // carries no invocation token, so the capability's own payload is what reaches `checkCapability`.
  // Its own claims are the last hop of the chain and have to bind like any other link's.
  async function presented(): Promise<{
    root: ReturnType<typeof randomIdentity>
    manager: ReturnType<typeof randomIdentity>
    device: ReturnType<typeof randomIdentity>
    leaf: CapabilityPayload
    parent: string
  }> {
    const root = randomIdentity()
    const manager = randomIdentity()
    const device = randomIdentity()
    // root → manager: write anything. manager → device: write `doc/1` only.
    const parent = stringifyToken(
      await createCapability(root, {
        sub: root.id,
        aud: manager.id,
        act: 'write',
        res: '*',
        exp: now() + 3600,
      }),
    )
    const leafToken = await createCapability(
      manager,
      {
        sub: root.id,
        aud: device.id,
        act: 'write',
        res: 'doc/1',
        exp: now() + 3600,
        cap: [parent],
      },
      undefined,
      { parentCapability: parent },
    )
    return { root, manager, device, leaf: leafToken.payload as CapabilityPayload, parent }
  }

  test('the presented capability grants what it names', async () => {
    const { leaf } = await presented()
    await expect(
      checkCapability({ act: 'write', res: 'doc/1' }, leaf as never),
    ).resolves.not.toThrow()
  })

  test('a request the presented capability does not name is refused, whatever its parent grants', async () => {
    const { leaf } = await presented()
    // The parent grants `write *`, so before the presented capability's own `res` was checked this
    // was accepted — the narrowing at the last hop was a no-op.
    await expect(checkCapability({ act: 'write', res: 'doc/999' }, leaf as never)).rejects.toThrow(
      'Invalid capability: permission not granted',
    )
  })

  test('an action the presented capability does not name is refused', async () => {
    const { root, manager, device, parent } = await presented()
    // Hand-signed: the mint path refuses a different action, and an attacker holding the key
    // signs whatever it likes. Only `act` differs from the capability the mint path would produce.
    const widened = await manager.signToken({
      sub: root.id,
      aud: device.id,
      act: 'read',
      res: '*',
      exp: now() + 3600,
      cap: [parent],
    })
    await expect(checkCapability({ act: 'write', res: 'doc/1' }, widened.payload)).rejects.toThrow(
      'Invalid capability: permission not granted',
    )
  })

  test('the parent still has to cover the presented capability, not merely the request', async () => {
    const { root, manager, device, parent } = await presented()
    // A leaf claiming more than its parent granted: `delete` was never delegated. The request is
    // within the leaf, so only the leaf-against-parent comparison can refuse it.
    const overreaching = await manager.signToken({
      sub: root.id,
      aud: device.id,
      act: ['write', 'delete'],
      res: '*',
      exp: now() + 3600,
      cap: [parent],
    })
    await expect(
      checkCapability({ act: 'delete', res: 'doc/1' }, overreaching.payload),
    ).rejects.toThrow('Invalid capability: permission mismatch')
  })

  test('an invocation names no grant of its own and is still checked against its chain', async () => {
    const root = randomIdentity()
    const device = randomIdentity()
    const capability = stringifyToken(
      await createCapability(root, {
        sub: root.id,
        aud: device.id,
        act: 'write',
        res: 'doc/1',
        exp: now() + 3600,
      }),
    )
    // The invocation shape: `act`/`res` absent, authority entirely in `cap`. Dropping the pair is
    // no escape — the leaf capability of the chain is what the request is checked against.
    const invocation = { iss: device.id, sub: root.id, cap: [capability] }
    await expect(
      checkCapability({ act: 'write', res: 'doc/1' }, invocation as never),
    ).resolves.not.toThrow()
    await expect(
      checkCapability({ act: 'write', res: 'doc/999' }, invocation as never),
    ).rejects.toThrow('Invalid capability: permission mismatch')
  })
})

describe('assertCapabilityToken with non-token input', () => {
  test('throws a domain error, not a TypeError', () => {
    expect(() => assertCapabilityToken(null)).toThrow('Invalid token: not a capability')
    expect(() => assertCapabilityToken(undefined)).toThrow('Invalid token: not a capability')
  })
})
