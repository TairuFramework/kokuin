import { encodeKey } from '@kokuin/controller'
import type {
  DIDMethodResolverResolveHistoricParams,
  DIDMethodResolverResolveParams,
  OwnIdentity,
} from '@kokuin/token'
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
  audienceConfirmation,
  type CapabilityPayload,
  checkCapability,
  checkDelegationChain,
  createCapability,
  hasPermission,
  isCapabilityToken,
  now,
} from '../src/index.js'

const at = <TValue>(items: ReadonlyArray<TValue>, i: number): TValue => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

describe('createCapability() - child expiry attenuation', () => {
  test.each([
    { name: 'earlier expiry', bounded: true, offset: -1, accepted: true },
    { name: 'equal expiry', bounded: true, offset: 0, accepted: true },
    { name: 'later expiry', bounded: true, offset: 1, accepted: false },
    { name: 'missing expiry', bounded: true, offset: undefined, accepted: false },
    { name: 'unbounded parent and child', bounded: false, offset: undefined, accepted: true },
    { name: 'unbounded parent and bounded child', bounded: false, offset: 1, accepted: true },
  ])('$name', async ({ bounded, offset, accepted }) => {
    const root = randomIdentity()
    const manager = randomIdentity()
    const device = randomIdentity()
    const expiry = now() + 3600
    const parent = await createCapability({
      signer: root,
      payload: {
        sub: root.id,
        aud: manager.id,
        act: 'write',
        res: '*',
        exp: bounded ? expiry : undefined,
      },
    })
    const result = createCapability({
      signer: manager,
      payload: {
        sub: root.id,
        aud: device.id,
        act: 'write',
        res: 'doc/1',
        exp: offset == null ? undefined : expiry + offset,
      },
      header: undefined,
      parentCapability: stringifyToken(parent),
    })
    if (accepted) {
      await expect(result).resolves.toMatchObject({ payload: { aud: device.id } })
    } else {
      await expect(result).rejects.toThrow(
        'Invalid capability: child expiry exceeds parent capability',
      )
    }
  })
})

describe('hasPermission()', () => {
  test('with single action and resource', () => {
    // Same action, different resources
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: 'foo/bar' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: 'foo/baz' },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: 'foo/*' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: '*' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: '' },
      }),
    ).toBe(false)
    // Same resource, different actions
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: 'foo/bar' },
      }),
    ).toBe(true)

    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/write', res: 'foo/bar' },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/*', res: 'foo/bar' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: '*', res: 'foo/bar' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: '', res: 'foo/bar' },
      }),
    ).toBe(false)
  })

  test('with multiple actions or resources granted, check for any match', () => {
    // Same action, different resources
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: ['foo/foo', 'foo/baz'] },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: ['foo/foo', 'foo/*'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: ['foo/foo', '*'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: ['foo/foo', ''] },
      }),
    ).toBe(false)
    // Same resource, different actions
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: ['test/other', 'test/read'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: ['test/other', 'test/write'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: ['test/other', 'test/*'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: ['test/other', '*'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: ['test/other', ''], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(false)
  })

  test('with multiple actions or resources expected, check for every match', () => {
    // Same action, different resources
    expect(
      hasPermission({
        expected: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        granted: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        granted: { act: 'test/read', res: ['foo/foo', 'foo/baz'] },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        granted: { act: 'test/read', res: ['foo/foo', 'foo/*'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        granted: { act: 'test/read', res: ['foo/foo', ''] },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        granted: { act: 'test/read', res: 'foo/*' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        granted: { act: 'test/read', res: '*' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: ['foo/foo', 'foo/bar'] },
        granted: { act: 'test/read', res: '' },
      }),
    ).toBe(false)
    // Same resource, different actions
    expect(
      hasPermission({
        expected: { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        granted: { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: ['test/read', 'test/delete'], res: ['foo/foo', 'foo/bar'] },
        granted: { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        granted: { act: ['test/read'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        granted: { act: ['test/read', 'test/*'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        granted: { act: ['test/read', '*'], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: ['test/read', 'test/write'], res: ['foo/foo', 'foo/bar'] },
        granted: { act: ['test/read', ''], res: ['foo/foo', 'foo/bar'] },
      }),
    ).toBe(false)
  })

  test('does not grant ancestor resources or actions (prefix escalation)', () => {
    // A grant more specific than the request must NOT authorize the broader request.
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar' },
        granted: { act: 'test/read', res: 'foo/bar/baz' },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo' },
        granted: { act: 'test/read', res: 'foo/bar/baz' },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test', res: 'foo/bar' },
        granted: { act: 'test/read', res: 'foo/bar' },
      }),
    ).toBe(false)

    // No implicit descent: a shorter grant does not cover a deeper request without `*`.
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar/baz' },
        granted: { act: 'test/read', res: 'foo/bar' },
      }),
    ).toBe(false)
    expect(
      hasPermission({
        expected: { act: 'test/read/extra', res: 'foo/bar' },
        granted: { act: 'test/read', res: 'foo/bar' },
      }),
    ).toBe(false)

    // Explicit trailing `*` is still required to authorize deeper requests.
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar/baz' },
        granted: { act: 'test/read', res: 'foo/*' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'test/read', res: 'foo/bar/baz' },
        granted: { act: 'test/read', res: 'foo/bar/*' },
      }),
    ).toBe(true)
  })
})

describe('assertNonExpired()', () => {
  test('with no expiration', () => {
    expect(() => assertNonExpired({ payload: {} })).not.toThrow()
    expect(() => assertNonExpired({ payload: { exp: undefined } })).not.toThrow()
  })

  test('with valid expiration', () => {
    const exp = now() + 1000
    expect(() => assertNonExpired({ payload: { exp } })).not.toThrow()
    expect(() => assertNonExpired({ payload: { exp }, atTime: exp - 100 })).not.toThrow()
  })

  test('with invalid expiration', () => {
    const exp = now() - 1000
    expect(() => assertNonExpired({ payload: { exp } })).toThrow('Invalid token: expired')
    expect(() => assertNonExpired({ payload: { exp: exp - 1000 }, atTime: exp })).toThrow(
      'Invalid token: expired',
    )
  })
})

describe('assertValidIssuedAt()', () => {
  test('accepts payload without iat', () => {
    expect(() => assertValidIssuedAt({ payload: {} })).not.toThrow()
    expect(() => assertValidIssuedAt({ payload: { iat: undefined } })).not.toThrow()
  })

  test('accepts payload with past iat', () => {
    const iat = now() - 1000
    expect(() => assertValidIssuedAt({ payload: { iat } })).not.toThrow()
  })

  test('accepts payload with current iat', () => {
    const iat = now()
    expect(() => assertValidIssuedAt({ payload: { iat } })).not.toThrow()
  })

  test('rejects payload with future iat', () => {
    const iat = now() + 1000
    expect(() => assertValidIssuedAt({ payload: { iat } })).toThrow(
      'Invalid token: issued in the future',
    )
  })

  test('respects atTime parameter', () => {
    const fixedTime = 1700000000
    // iat is before atTime — OK
    expect(() =>
      assertValidIssuedAt({ payload: { iat: fixedTime - 100 }, atTime: fixedTime }),
    ).not.toThrow()
    // iat is after atTime — rejected
    expect(() =>
      assertValidIssuedAt({ payload: { iat: fixedTime + 100 }, atTime: fixedTime }),
    ).toThrow('Invalid token: issued in the future')
  })
})

describe('assertValidDelegation()', () => {
  test('checks matching issuer and audience', () => {
    expect(() => {
      assertValidDelegation({
        from: { aud: 'did:test:123' } as CapabilityPayload,
        to: { iss: 'did:test:123' } as CapabilityPayload,
      })
    }).not.toThrow()
    expect(() => {
      assertValidDelegation({
        from: { aud: 'did:test:456' } as CapabilityPayload,
        to: { iss: 'did:test:123' } as CapabilityPayload,
      })
    }).toThrow('Invalid capability: audience mismatch')
  })

  test('checks matching subject', () => {
    expect(() => {
      assertValidDelegation({
        from: { aud: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
        to: { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
      })
    }).not.toThrow()
    expect(() => {
      assertValidDelegation({
        from: { aud: 'did:test:123', sub: 'did:test:789' } as CapabilityPayload,
        to: { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
      })
    }).toThrow('Invalid capability: subject mismatch')
  })

  test('checks expired parent', () => {
    expect(() => {
      assertValidDelegation({
        from: { aud: 'did:test:123', sub: 'did:test:456', exp: now() + 1000 } as CapabilityPayload,
        to: { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
      })
    }).not.toThrow()
    expect(() => {
      assertValidDelegation({
        from: { aud: 'did:test:123', sub: 'did:test:456', exp: now() - 1000 } as CapabilityPayload,
        to: { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
      })
    }).toThrow('Invalid token: expired')
  })

  test('checks matching actions and resources', () => {
    expect(() => {
      assertValidDelegation({
        from: {
          aud: 'did:test:123',
          sub: 'did:test:456',
          act: 'test',
          res: 'foo/*',
        } as CapabilityPayload,
        to: {
          iss: 'did:test:123',
          sub: 'did:test:456',
          act: 'test',
          res: ['foo/bar', 'foo/baz'],
        } as CapabilityPayload,
      })
    }).not.toThrow()
    expect(() => {
      assertValidDelegation({
        from: {
          aud: 'did:test:123',
          sub: 'did:test:456',
          act: 'test',
          res: ['foo/bar', 'foo/foo'],
        } as CapabilityPayload,
        to: {
          iss: 'did:test:123',
          sub: 'did:test:456',
          act: 'test',
          res: ['foo/bar', 'foo/baz'],
        } as CapabilityPayload,
      })
    }).toThrow('Invalid capability: permission mismatch')
  })
})

describe('checkDelegationChain()', () => {
  test('last payload should be issued by subject and not expired', async () => {
    await expect(
      checkDelegationChain({
        payload: { iss: 'did:test:123', sub: 'did:test:123' } as CapabilityPayload,
        capabilities: [],
      }),
    ).resolves.toBeUndefined()
    await expect(async () => {
      await checkDelegationChain({
        payload: {
          iss: 'did:test:123',
          sub: 'did:test:123',
          exp: now() - 1000,
        } as CapabilityPayload,
        capabilities: [],
      })
    }).rejects.toThrow('Invalid token: expired')
    // Same three time claims as the member arm beside it and the subject arm of `checkCapability`.
    await expect(
      checkDelegationChain({
        payload: {
          iss: 'did:test:123',
          sub: 'did:test:123',
          nbf: now() + 1000,
        } as unknown as CapabilityPayload,
        capabilities: [],
      }),
    ).rejects.toThrow('Invalid token: not yet valid')
    await expect(async () => {
      await checkDelegationChain({
        payload: { iss: 'did:test:123', sub: 'did:test:456' } as CapabilityPayload,
        capabilities: [],
      })
    }).rejects.toThrow('Invalid capability: issuer should be subject')
  })

  test('validates the full chain', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()
    const signerC = randomIdentity()
    const signerD = randomIdentity()
    const delegateToB = await createCapability({
      signer: signerA,
      payload: {
        sub: signerA.id,
        aud: signerB.id,
        act: '*',
        res: 'foo/*',
      },
    })
    const delegateToC = await createCapability({
      signer: signerB,
      payload: {
        sub: signerA.id,
        aud: signerC.id,
        act: 'test/*',
        res: ['foo/bar', 'foo/baz'],
      },
      header: undefined,
      parentCapability: stringifyToken(delegateToB),
    })
    const delegateToD = await createCapability({
      signer: signerC,
      payload: {
        sub: signerA.id,
        aud: signerD.id,
        act: ['test/read', 'test/write'],
        res: 'foo/baz',
      },
      header: undefined,
      parentCapability: stringifyToken(delegateToC),
    })
    await expect(
      checkDelegationChain({
        payload: delegateToD.payload,
        capabilities: [stringifyToken(delegateToC), stringifyToken(delegateToB)],
      }),
    ).resolves.not.toThrow()
  })
})

describe('checkCapability()', () => {
  test('validates the full chain', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()
    const signerC = randomIdentity()
    const signerD = randomIdentity()
    const delegateToB = await createCapability({
      signer: signerA,
      payload: {
        sub: signerA.id,
        aud: signerB.id,
        act: '*',
        res: ['foo/*'],
      },
    })
    const delegateToC = await createCapability({
      signer: signerB,
      payload: {
        sub: signerA.id,
        aud: signerC.id,
        act: 'test/*',
        res: ['foo/bar', 'foo/baz'],
      },
      header: undefined,
      parentCapability: stringifyToken(delegateToB),
    })
    const delegateToD = await createCapability({
      signer: signerC,
      payload: {
        sub: signerA.id,
        aud: signerD.id,
        act: 'test/*',
        res: ['foo/baz'],
      },
      header: undefined,
      parentCapability: stringifyToken(delegateToC),
    })
    const token = await signerD.signToken({
      payload: {
        sub: signerA.id,
        prc: 'test/call',
        cap: [
          stringifyToken(delegateToD),
          stringifyToken(delegateToC),
          stringifyToken(delegateToB),
        ],
      },
    })
    await expect(
      checkCapability({ permission: { act: 'test/call', res: 'foo/baz' }, payload: token.payload }),
    ).resolves.not.toThrow()
  })

  test('rejects expired capability token', async () => {
    const fixedTime = 1700000000
    const alice = randomIdentity()
    const bob = randomIdentity()

    const capability = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: 'test/read',
        res: 'foo/bar',
        exp: fixedTime - 100, // Expired
      },
    })

    const bobToken = await bob.signToken({
      payload: {
        sub: alice.id,
        act: 'test/read',
        res: 'foo/bar',
        cap: stringifyToken(capability),
      },
    })

    await expect(
      checkCapability({
        permission: { act: 'test/read', res: 'foo/bar' },
        payload: bobToken.payload,
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

    const capability = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: 'test/read',
        res: 'foo/bar',
        exp: referenceTime + 100,
      },
    })

    const bobToken = await bob.signToken({
      payload: {
        sub: alice.id,
        act: 'test/read',
        res: 'foo/bar',
        exp: referenceTime + 100,
        cap: stringifyToken(capability),
      },
    })

    await expect(
      checkCapability({
        permission: { act: 'test/read', res: 'foo/bar' },
        payload: bobToken.payload,
        atTime: referenceTime,
      }),
    ).resolves.not.toThrow()
  })

  test('forwards verifiers to every capability in the chain', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()
    const capability = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: 'test/read',
        res: 'foo/bar',
      },
    })
    const bobToken = await bob.signToken({
      payload: {
        sub: alice.id,
        act: 'test/read',
        res: 'foo/bar',
        cap: stringifyToken(capability),
      },
    })
    const permission = { act: 'test/read', res: 'foo/bar' }

    await expect(
      checkCapability({ permission, payload: bobToken.payload }),
    ).resolves.toBeUndefined()
    const EdDSA = vi.fn(() => false)
    await expect(
      checkCapability({
        permission,
        payload: bobToken.payload,
        verifiers: { EdDSA },
      }),
    ).rejects.toThrow()
    expect(EdDSA).toHaveBeenCalled()
  })
})

describe('checkCapability() - self-issued tokens (C-02)', () => {
  test('validates permissions even for self-issued tokens', async () => {
    const alice = randomIdentity()

    // Alice creates a self-issued token claiming only 'read' permission
    const token = await alice.signToken({
      payload: {
        sub: alice.id,
        act: 'test/read',
        res: 'foo/bar',
      },
    })

    // Should succeed: requesting exactly what was granted
    await expect(
      checkCapability({ permission: { act: 'test/read', res: 'foo/bar' }, payload: token.payload }),
    ).resolves.not.toThrow()

    // Should FAIL: requesting 'write' when only 'read' was granted
    // BUG: Currently passes because iss === sub bypasses permission check
    await expect(
      checkCapability({
        permission: { act: 'test/write', res: 'foo/bar' },
        payload: token.payload,
      }),
    ).rejects.toThrow()
  })

  test('validates resource even for self-issued tokens', async () => {
    const alice = randomIdentity()

    const token = await alice.signToken({
      payload: {
        sub: alice.id,
        act: 'test/read',
        res: 'foo/bar',
      },
    })

    // Should FAIL: requesting different resource
    await expect(
      checkCapability({ permission: { act: 'test/read', res: 'foo/baz' }, payload: token.payload }),
    ).rejects.toThrow()
  })

  test('respects wildcard permissions for self-issued tokens', async () => {
    const alice = randomIdentity()

    const token = await alice.signToken({
      payload: {
        sub: alice.id,
        act: '*',
        res: 'foo/*',
      },
    })

    // Should succeed: wildcard covers this
    await expect(
      checkCapability({ permission: { act: 'test/read', res: 'foo/bar' }, payload: token.payload }),
    ).resolves.not.toThrow()

    // Should fail: resource doesn't match wildcard
    await expect(
      checkCapability({ permission: { act: 'test/read', res: 'bar/baz' }, payload: token.payload }),
    ).rejects.toThrow()
  })

  test('requires act and res claims for self-issued tokens', async () => {
    const alice = randomIdentity()

    // Token without act/res claims
    const token = await alice.signToken({
      payload: {
        sub: alice.id,
      },
    })

    await expect(
      checkCapability({ permission: { act: 'test/read', res: 'foo/bar' }, payload: token.payload }),
    ).rejects.toThrow()
  })
})

describe('checkDelegationChain() - depth limits (H-04)', () => {
  async function buildDelegationChain(signers: Array<OwnIdentity>) {
    const capabilities: Array<string> = []
    for (let i = 0; i < signers.length - 1; i++) {
      const parentOption = i > 0 ? { parentCapability: capabilities[i - 1] } : undefined
      const cap = await createCapability({
        signer: at(signers, i),
        payload: {
          sub: at(signers, 0).id,
          aud: at(signers, i + 1).id,
          act: '*',
          res: '*',
        },
        header: undefined,
        ...parentOption,
      })
      capabilities.push(stringifyToken(cap))
    }
    return capabilities
  }

  test('rejects delegation chains exceeding max depth', async () => {
    const signers = Array.from({ length: 25 }, () => randomIdentity())

    const capabilities = await buildDelegationChain(signers)

    const finalPayload = {
      iss: at(signers, signers.length - 1).id,
      sub: at(signers, 0).id,
      act: 'test',
      res: 'foo',
    } as CapabilityPayload

    // Should reject: chain depth exceeds limit
    await expect(
      checkDelegationChain({ payload: finalPayload, capabilities: [...capabilities].reverse() }),
    ).rejects.toThrow('delegation chain exceeds maximum depth')
  })

  test('accepts delegation chains within max depth', async () => {
    const signers = Array.from({ length: 5 }, () => randomIdentity())

    const capabilities = await buildDelegationChain(signers)

    const finalPayload = {
      iss: at(signers, signers.length - 1).id,
      sub: at(signers, 0).id,
      act: 'test',
      res: 'foo',
    } as CapabilityPayload

    // Should succeed: chain depth within limit
    await expect(
      checkDelegationChain({ payload: finalPayload, capabilities: [...capabilities].reverse() }),
    ).resolves.not.toThrow()
  })

  test('counts the capability checkCapability peels off against maxDepth', async () => {
    // `checkCapability` splits `cap` into a head it verifies itself and a tail it hands to
    // `checkDelegationChain`, so the bound applied to the tail alone admitted one more link than
    // the default names. Five links must be refused at a default of four; four must pass.
    const signers = Array.from({ length: 6 }, () => randomIdentity())
    const capabilities = await buildDelegationChain(signers)
    const invocation = {
      iss: at(signers, signers.length - 1).id,
      sub: at(signers, 0).id,
    } as CapabilityPayload

    await expect(
      checkCapability({
        permission: { act: 'test', res: 'foo' },
        payload: {
          ...invocation,
          cap: [...capabilities].reverse(),
        } as CapabilityPayload,
      }),
    ).rejects.toThrow('delegation chain exceeds maximum depth of 4')

    await expect(
      checkCapability({
        permission: { act: 'test', res: 'foo' },
        payload: {
          ...invocation,
          iss: at(signers, 4).id,
          cap: [...capabilities.slice(0, 4)].reverse(),
        } as CapabilityPayload,
      }),
    ).resolves.not.toThrow()
  })

  test('respects custom maxDepth option', async () => {
    const signers = Array.from({ length: 5 }, () => randomIdentity())

    const capabilities = await buildDelegationChain(signers)

    const finalPayload = {
      iss: at(signers, signers.length - 1).id,
      sub: at(signers, 0).id,
      act: 'test',
      res: 'foo',
    } as CapabilityPayload

    const reversed = [...capabilities].reverse()

    // Should reject: custom limit of 2
    await expect(
      checkDelegationChain({ payload: finalPayload, capabilities: reversed, maxDepth: 2 }),
    ).rejects.toThrow('delegation chain exceeds maximum depth')

    // Should succeed: custom limit of 10
    await expect(
      checkDelegationChain({ payload: finalPayload, capabilities: reversed, maxDepth: 10 }),
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
      payload: {
        sub: identity.id,
        aud: 'did:test:789',
        act: 'test',
        res: 'foo',
      } as Record<string, unknown>,
    })
    const branded = await verifyToken({ token: signed })
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
    expect(() => assertValidDelegation({ from, to, atTime: fixedTime })).not.toThrow()
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
    await expect(checkDelegationChain({ payload, capabilities: [] })).resolves.not.toThrow()
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

  test('accepts a key fragment, which a revoke permission names as its resource', () => {
    // A `did:kokuin:` `rev` may target a key, spelled `#<multibase key>`, and the revoke permission
    // is `{ act: 'revoke', res: <target> }`. Without `#` the only grant that could authorise
    // revoking a key would be `res: '*'` — a wildcard has to be a whole component — so delegating
    // "retire this one leaked key" would have meant delegating "revoke anything".
    expect(() => {
      return assertValidPattern('#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')
    }).not.toThrow()
    // Still not a licence for wildcards inside a component.
    expect(() => assertValidPattern('#z6Mk*')).toThrow('Invalid pattern')
  })

  test('a key fragment matches itself and nothing else', () => {
    // `#` is inert to the matcher: components are compared whole. Asserted rather than assumed,
    // because widening the character class is only safe if it adds no matching behaviour.
    const key = '#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const other = '#z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
    expect(
      hasPermission({
        expected: { act: 'revoke', res: key },
        granted: { act: 'revoke', res: key },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'revoke', res: key },
        granted: { act: 'revoke', res: other },
      }),
    ).toBe(false)
    // A wildcard still covers it, and the fragment does not become one.
    expect(
      hasPermission({
        expected: { act: 'revoke', res: key },
        granted: { act: 'revoke', res: '*' },
      }),
    ).toBe(true)
    expect(
      hasPermission({
        expected: { act: 'revoke', res: other },
        granted: { act: 'revoke', res: key },
      }),
    ).toBe(false)
  })
})

describe('createCapability() - delegation validation (C-03)', () => {
  test('creates capability when signer is the subject (root capability)', async () => {
    const alice = randomIdentity()

    // Alice creates a capability for herself - always allowed
    const cap = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: 'did:test:bob',
        act: 'test/read',
        res: 'foo/bar',
      },
    })

    expect(cap.payload.iss).toBe(alice.id)
    expect(cap.payload.sub).toBe(alice.id)
  })

  test('creates capability with parent validation when delegating', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    // Alice creates root capability for Bob
    const rootCap = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: '*',
        res: 'foo/*',
      },
    })

    // Bob can delegate to Carol with valid parent
    const carol = randomIdentity()
    const delegatedCap = await createCapability({
      signer: bob,
      payload: {
        sub: alice.id,
        aud: carol.id,
        act: 'test/read',
        res: 'foo/bar',
      },
      header: undefined,
      parentCapability: stringifyToken(rootCap),
    })

    expect(delegatedCap.payload.iss).toBe(bob.id)
    expect(delegatedCap.payload.sub).toBe(alice.id)
  })

  test('rejects delegation that exceeds parent permissions', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    const rootCap = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: 'test/read', // Only read
        res: 'foo/bar',
      },
    })

    const carol = randomIdentity()

    // Bob tries to delegate 'write' which he doesn't have
    await expect(
      createCapability({
        signer: bob,
        payload: {
          sub: alice.id,
          aud: carol.id,
          act: 'test/write', // Exceeds parent
          res: 'foo/bar',
        },
        header: undefined,
        parentCapability: stringifyToken(rootCap),
      }),
    ).rejects.toThrow('permission')
  })

  test('rejects delegation without parentCapability when signer is not subject', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    // Bob tries to delegate for Alice without providing a parent capability
    await expect(
      createCapability({
        signer: bob,
        payload: {
          sub: alice.id,
          aud: 'did:test:carol',
          act: 'test/read',
          res: 'foo/bar',
        },
      }),
    ).rejects.toThrow('parentCapability required')
  })

  test('rejects delegation when signer is not the parent audience', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()
    const eve = randomIdentity() // Attacker

    const rootCap = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: '*',
        res: '*',
      },
    })

    // Eve tries to use Bob's capability
    await expect(
      createCapability({
        signer: eve,
        payload: {
          sub: alice.id,
          aud: 'did:test:victim',
          act: '*',
          res: '*',
        },
        header: undefined,
        parentCapability: stringifyToken(rootCap),
      }),
    ).rejects.toThrow('audience')
  })

  test('delegates from a did:kokuin: root when methods is provided, and fails without it', async () => {
    // A DID whose keys cannot be recovered from the identifier -- the shape `did:kokuin:` has.
    // The resolver here is a hand-built fake: this package must not depend on
    // `@kokuin/controller`, and a real folded log would prove nothing extra about the option
    // threading. Mirrors the idiom in `test/method-registry.test.ts`.
    const profileDID = 'did:kokuin:zTestProfile' as DIDString
    const root = createSigningIdentityForDID({ id: profileDID, privateKey: randomPrivateKey() })
    const resolver: DIDMethodResolver = {
      method: 'kokuin',
      resolve: async ({ did }: DIDMethodResolverResolveParams) => {
        if (did !== profileDID) {
          throw new Error(`Unknown DID: ${did}`)
        }
        return { alg: 'EdDSA', publicKey: root.publicKey }
      },
      // One fixed key, so historic and current coincide — but it still has to be published, since
      // a capability is archived material and `verifyToken` asks for it.
      resolveHistoric: async ({ did }: DIDMethodResolverResolveHistoricParams) => {
        if (did !== profileDID) {
          throw new Error(`Unknown DID: ${did}`)
        }
        return { alg: 'EdDSA', publicKey: root.publicKey }
      },
    }
    const bob = randomIdentity()
    const carol = randomIdentity()

    const rootCap = await createCapability({
      signer: root,
      payload: {
        sub: profileDID,
        aud: bob.id,
        act: '*',
        res: 'foo/*',
      },
    })

    const delegated = await createCapability({
      signer: bob,
      payload: {
        sub: profileDID,
        aud: carol.id,
        act: 'test/read',
        res: 'foo/bar',
      },
      header: undefined,
      parentCapability: stringifyToken(rootCap),
      methods: [resolver],
    })
    expect(delegated.payload.iss).toBe(bob.id)
    expect(delegated.payload.sub).toBe(profileDID)

    // Without the registry, the did:kokuin: parent capability cannot be verified at all -- an
    // implementation that ignores `methods` here would pass the assertion above but not this one.
    await expect(
      createCapability({
        signer: bob,
        payload: {
          sub: profileDID,
          aud: carol.id,
          act: 'test/read',
          res: 'foo/bar',
        },
        header: undefined,
        parentCapability: stringifyToken(rootCap),
      }),
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
    const rootCap = await alice.signToken({
      payload: { sub: alice.id, aud: bob.id, act: '*', res: 'foo/*' },
      embedLongForm: false,
    })
    const cache = createInMemoryDIDCache()
    await cache.set({ shortForm: alice.id, doc: alice.doc })

    // Note: no `resolver` anywhere in this test -- this isolates `cache` from `resolver`, so a
    // future implementation that forwards `resolver` but not `cache` cannot pass this test by
    // accident.
    const delegated = await createCapability({
      signer: bob,
      payload: { sub: alice.id, aud: carol.id, act: 'test/read', res: 'foo/bar' },
      header: undefined,
      parentCapability: stringifyToken(rootCap),
      cache,
    })
    // First contact with carol: bob's own signer embeds his long form, unrelated to the option
    // under test.
    expect(delegated.payload.iss).toBe(bob.longForm)
    expect(delegated.payload.sub).toBe(alice.id)

    // Without the cache, an implementation that ignores it here would pass the assertion above
    // but not this one.
    await expect(
      createCapability({
        signer: bob,
        payload: { sub: alice.id, aud: carol.id, act: 'test/read', res: 'foo/bar' },
        header: undefined,
        parentCapability: stringifyToken(rootCap),
      }),
    ).rejects.toThrow(`Unknown DID: ${alice.id}`)
  })

  test('delegates from a did:peer:4 short-form root when resolver is provided, and fails without it', async () => {
    // Isolates `resolver` from `cache`: no `cache` anywhere in this test, on either call, so a
    // resolver-only path is the only way the short-form root capability's issuer can resolve.
    // Models the sibling resolver-only case in `test/revocation.test.ts`.
    const alice = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const bob = randomIdentity()
    const carol = randomIdentity()

    // Alice signs with her short form: without a resolver (or a cache entry), nothing can turn
    // that short form back into her signing key.
    const rootCap = await alice.signToken({
      payload: { sub: alice.id, aud: bob.id, act: '*', res: 'foo/*' },
      embedLongForm: false,
    })
    const doc = decodePeer4({ longForm: alice.longForm }).doc
    const resolver: DIDResolver = (did: string) => (did === alice.id ? doc : undefined)

    const delegated = await createCapability({
      signer: bob,
      payload: { sub: alice.id, aud: carol.id, act: 'test/read', res: 'foo/bar' },
      header: undefined,
      parentCapability: stringifyToken(rootCap),
      resolver,
    })
    expect(delegated.payload.iss).toBe(bob.id)
    expect(delegated.payload.sub).toBe(alice.id)

    // Without the resolver, an implementation that ignores it here would pass the assertion
    // above but not this one.
    await expect(
      createCapability({
        signer: bob,
        payload: { sub: alice.id, aud: carol.id, act: 'test/read', res: 'foo/bar' },
        header: undefined,
        parentCapability: stringifyToken(rootCap),
      }),
    ).rejects.toThrow(`Unknown DID: ${alice.id}`)
  })
})

describe('verifyToken hook', () => {
  test('checkDelegationChain calls verifyToken for each token in the chain', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()
    const signerC = randomIdentity()

    const delegateToB = await createCapability({
      signer: signerA,
      payload: {
        sub: signerA.id,
        aud: signerB.id,
        act: '*',
        res: '*',
      },
    })
    const delegateToC = await createCapability({
      signer: signerB,
      payload: {
        sub: signerA.id,
        aud: signerC.id,
        act: 'test/*',
        res: 'foo/*',
      },
      header: undefined,
      parentCapability: stringifyToken(delegateToB),
    })

    const verified: Array<string> = []
    const verifyToken = vi.fn(({ token: _token, raw }: { token: unknown; raw: string }) => {
      verified.push(raw)
    })

    await checkDelegationChain({
      payload: delegateToC.payload,
      capabilities: [stringifyToken(delegateToB)],
      verifyToken,
    })

    expect(verifyToken).toHaveBeenCalledTimes(1)
    expect(verified[0]).toBe(stringifyToken(delegateToB))
  })

  test('checkDelegationChain rejects when verifyToken throws', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()

    const delegateToB = await createCapability({
      signer: signerA,
      payload: {
        sub: signerA.id,
        aud: signerB.id,
        act: '*',
        res: '*',
      },
    })

    const verifyToken = vi.fn(() => {
      throw new Error('Token revoked')
    })

    await expect(
      checkDelegationChain({
        payload: delegateToB.payload,
        capabilities: [stringifyToken(delegateToB)],
        verifyToken,
      }),
    ).rejects.toThrow('Token revoked')
  })

  test('checkCapability calls verifyToken for capability tokens', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    const capability = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: 'test/read',
        res: 'foo/bar',
      },
    })

    const capString = stringifyToken(capability)
    const token = await bob.signToken({
      payload: {
        sub: alice.id,
        prc: 'test/read',
        cap: capString,
      },
    })

    const verifyTokenHook = vi.fn()

    await checkCapability({
      permission: { act: 'test/read', res: 'foo/bar' },
      payload: token.payload,
      verifyToken: verifyTokenHook,
    })

    expect(verifyTokenHook).toHaveBeenCalledTimes(1)
    expect(verifyTokenHook).toHaveBeenCalledWith({
      token: expect.objectContaining({
        payload: expect.objectContaining({ iss: alice.id, aud: bob.id }),
      }),
      raw: capString,
    })
  })

  test('checkCapability rejects when verifyToken throws for capability', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    const capability = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: 'test/read',
        res: 'foo/bar',
      },
    })

    const token = await bob.signToken({
      payload: {
        sub: alice.id,
        prc: 'test/read',
        cap: stringifyToken(capability),
      },
    })

    const verifyTokenHook = vi.fn(() => {
      throw new Error('Token revoked')
    })

    await expect(
      checkCapability({
        permission: { act: 'test/read', res: 'foo/bar' },
        payload: token.payload,
        verifyToken: verifyTokenHook,
      }),
    ).rejects.toThrow('Token revoked')
  })

  test('checkCapability does not call verifyToken for self-issued tokens', async () => {
    const alice = randomIdentity()

    const token = await alice.signToken({
      payload: {
        sub: alice.id,
        act: 'test/read',
        res: 'foo/bar',
      },
    })

    const verifyTokenHook = vi.fn()

    await checkCapability({
      permission: { act: 'test/read', res: 'foo/bar' },
      payload: token.payload,
      verifyToken: verifyTokenHook,
    })

    expect(verifyTokenHook).not.toHaveBeenCalled()
  })

  test('checkCapability calls verifyToken for full delegation chain', async () => {
    const signerA = randomIdentity()
    const signerB = randomIdentity()
    const signerC = randomIdentity()

    const delegateToB = await createCapability({
      signer: signerA,
      payload: {
        sub: signerA.id,
        aud: signerB.id,
        act: '*',
        res: 'foo/*',
      },
    })
    const delegateToC = await createCapability({
      signer: signerB,
      payload: {
        sub: signerA.id,
        aud: signerC.id,
        act: 'test/*',
        res: 'foo/bar',
      },
      header: undefined,
      parentCapability: stringifyToken(delegateToB),
    })

    const token = await signerC.signToken({
      payload: {
        sub: signerA.id,
        prc: 'test/call',
        cap: [stringifyToken(delegateToC), stringifyToken(delegateToB)],
      },
    })

    const verifyTokenHook = vi.fn()

    await checkCapability({
      permission: { act: 'test/call', res: 'foo/bar' },
      payload: token.payload,
      verifyToken: verifyTokenHook,
    })

    // Should be called for both tokens in the chain
    expect(verifyTokenHook).toHaveBeenCalledTimes(2)
  })

  test('checkCapability supports async verifyToken', async () => {
    const alice = randomIdentity()
    const bob = randomIdentity()

    const capability = await createCapability({
      signer: alice,
      payload: {
        sub: alice.id,
        aud: bob.id,
        act: 'test/read',
        res: 'foo/bar',
      },
    })

    const token = await bob.signToken({
      payload: {
        sub: alice.id,
        prc: 'test/read',
        cap: stringifyToken(capability),
      },
    })

    const verifyTokenHook = vi.fn(async () => {
      // Simulate async revocation check
      await new Promise((resolve) => setTimeout(resolve, 1))
    })

    await checkCapability({
      permission: { act: 'test/read', res: 'foo/bar' },
      payload: token.payload,
      verifyToken: verifyTokenHook,
    })

    expect(verifyTokenHook).toHaveBeenCalledTimes(1)
  })
})

describe('checkCapability() - a capability presented directly rather than invoked', () => {
  // A capability carries no invocation token, so its own payload is what reaches `checkCapability`.
  // Its own claims are the last hop of the chain and have to bind like any other link's.
  async function presented(): Promise<{
    root: OwnIdentity
    manager: OwnIdentity
    device: OwnIdentity
    leaf: CapabilityPayload
    parent: string
  }> {
    const root = randomIdentity()
    const manager = randomIdentity()
    const device = randomIdentity()
    // One stamp: reading the clock per token lets a second boundary push the child past its parent.
    const exp = now() + 3600
    // root → manager: write anything. manager → device: write `doc/1` only.
    const parent = stringifyToken(
      await createCapability({
        signer: root,
        payload: {
          sub: root.id,
          aud: manager.id,
          act: 'write',
          res: '*',
          exp,
        },
      }),
    )
    const leafToken = await createCapability({
      signer: manager,
      payload: {
        sub: root.id,
        aud: device.id,
        act: 'write',
        res: 'doc/1',
        exp,
        cap: [parent],
      },
      header: undefined,
      parentCapability: parent,
    })
    return { root, manager, device, leaf: leafToken.payload as CapabilityPayload, parent }
  }

  test('the presented capability grants what it names', async () => {
    const { leaf } = await presented()
    await expect(
      checkCapability({ permission: { act: 'write', res: 'doc/1' }, payload: leaf as never }),
    ).resolves.not.toThrow()
  })

  test('a request the presented capability does not name is refused, whatever its parent grants', async () => {
    const { leaf } = await presented()
    // The parent grants `write *`, so before the presented capability's own `res` was checked this
    // was accepted — the narrowing at the last hop was a no-op.
    await expect(
      checkCapability({ permission: { act: 'write', res: 'doc/999' }, payload: leaf as never }),
    ).rejects.toThrow('Invalid capability: permission not granted')
  })

  test('an action the presented capability does not name is refused', async () => {
    const { root, manager, device, parent } = await presented()
    // Hand-signed: the mint path refuses a different action, and an attacker holding the key
    // signs whatever it likes. Only `act` differs from the capability the mint path would produce.
    const widened = await manager.signToken({
      payload: {
        sub: root.id,
        aud: device.id,
        act: 'read',
        res: '*',
        exp: now() + 3600,
        cap: [parent],
      },
    })
    await expect(
      checkCapability({ permission: { act: 'write', res: 'doc/1' }, payload: widened.payload }),
    ).rejects.toThrow('Invalid capability: permission not granted')
  })

  test('the parent still has to cover the presented capability, not merely the request', async () => {
    const { root, manager, device, parent } = await presented()
    // A leaf claiming more than its parent granted: `delete` was never delegated. The request is
    // within the leaf, so only the leaf-against-parent comparison can refuse it.
    const overreaching = await manager.signToken({
      payload: {
        sub: root.id,
        aud: device.id,
        act: ['write', 'delete'],
        res: '*',
        exp: now() + 3600,
        cap: [parent],
      },
    })
    await expect(
      checkCapability({
        permission: { act: 'delete', res: 'doc/1' },
        payload: overreaching.payload,
      }),
    ).rejects.toThrow('Invalid capability: permission mismatch')
  })

  test('an invocation names no grant of its own and is still checked against its chain', async () => {
    const root = randomIdentity()
    const device = randomIdentity()
    const capability = stringifyToken(
      await createCapability({
        signer: root,
        payload: {
          sub: root.id,
          aud: device.id,
          act: 'write',
          res: 'doc/1',
          exp: now() + 3600,
        },
      }),
    )
    // The invocation shape: `act`/`res` absent, authority entirely in `cap`. Dropping the pair is
    // no escape — the leaf capability of the chain is what the request is checked against.
    const invocation = { iss: device.id, sub: root.id, cap: [capability] }
    await expect(
      checkCapability({ permission: { act: 'write', res: 'doc/1' }, payload: invocation as never }),
    ).resolves.not.toThrow()
    await expect(
      checkCapability({
        permission: { act: 'write', res: 'doc/999' },
        payload: invocation as never,
      }),
    ).rejects.toThrow('Invalid capability: permission mismatch')
  })

  describe('its own time claims, one at a time', () => {
    // A presented capability never passes through `verifyToken` here — the caller verified it and
    // handed over the payload — and the chain walk starts at its parent, so nothing else in this
    // package looks at these three. Each row moves exactly one claim; the parent is minted sound
    // and identical every time, so a rejection is the claim under test and nothing around it.
    const reference = 1700000000

    async function leafWith(claims: Record<string, unknown>): Promise<CapabilityPayload> {
      const root = randomIdentity()
      const manager = randomIdentity()
      const device = randomIdentity()
      const parent = stringifyToken(
        await createCapability({
          signer: root,
          payload: {
            sub: root.id,
            aud: manager.id,
            act: 'write',
            res: '*',
            exp: reference + 7200,
          },
        }),
      )
      // Hand-signed: the mint path would refuse some of these outright, and what is under test is
      // the verifier rather than the minter.
      const leaf = await manager.signToken({
        payload: {
          sub: root.id,
          aud: device.id,
          act: 'write',
          res: '*',
          cap: [parent],
          ...claims,
        },
      })
      return leaf.payload as CapabilityPayload
    }

    test('sound claims verify at the reference time', async () => {
      const leaf = await leafWith({
        exp: reference + 3600,
        nbf: reference - 60,
        iat: reference - 60,
      })
      await expect(
        checkCapability({
          permission: { act: 'write', res: 'doc/1' },
          payload: leaf as never,
          atTime: reference,
        }),
      ).resolves.not.toThrow()
    })

    test('an expired one is refused', async () => {
      const leaf = await leafWith({ exp: reference - 1 })
      await expect(
        checkCapability({
          permission: { act: 'write', res: 'doc/1' },
          payload: leaf as never,
          atTime: reference,
        }),
      ).rejects.toThrow('Invalid token: expired')
    })

    test('a not-yet-valid one is refused', async () => {
      const leaf = await leafWith({ exp: reference + 3600, nbf: reference + 60 })
      await expect(
        checkCapability({
          permission: { act: 'write', res: 'doc/1' },
          payload: leaf as never,
          atTime: reference,
        }),
      ).rejects.toThrow('Invalid token: not yet valid')
    })

    test('one issued in the future is refused', async () => {
      const leaf = await leafWith({ exp: reference + 3600, iat: reference + 60 })
      await expect(
        checkCapability({
          permission: { act: 'write', res: 'doc/1' },
          payload: leaf as never,
          atTime: reference,
        }),
      ).rejects.toThrow('Invalid token: issued in the future')
    })
  })
})

describe('assertCapabilityToken with non-token input', () => {
  test('throws a domain error, not a TypeError', () => {
    expect(() => assertCapabilityToken(null)).toThrow('Invalid token: not a capability')
    expect(() => assertCapabilityToken(undefined)).toThrow('Invalid token: not a capability')
  })
})

describe('audienceConfirmation()', () => {
  test('encodes the key exactly as a controller log encodes `k`', () => {
    // The two packages share the format, not the code (importing the controller's encoder from here
    // would cycle), so this is what keeps a log and a capability comparable by eye.
    const { publicKey } = randomIdentity()
    expect(audienceConfirmation({ alg: 'EdDSA', publicKey })).toEqual({
      kid: encodeKey({ publicKey, alg: 'EdDSA' }),
    })
  })

  test('the controller capability verifier is gone from the package surface', async () => {
    const capability = await import('../src/index.js')
    expect('createControllerCapabilityVerifier' in capability).toBe(false)
    expect('assertRevokeCapabilityAudience' in capability).toBe(false)
  })
})
