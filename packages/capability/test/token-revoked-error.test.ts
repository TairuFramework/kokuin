import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  keyTarget,
  type SignedEvent,
} from '@kokuin/controller'
import { createSigningIdentity, type MethodRegistry, stringifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  createCapability,
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
  isTokenRevokedError,
  now,
  TokenRevokedError,
} from '../src/index.js'

async function rejection(run: () => unknown): Promise<unknown> {
  try {
    await run()
  } catch (error) {
    return error
  }
  throw new Error('expected rejection')
}

describe('TokenRevokedError', () => {
  test('verified path: a revoked capability is refused with a branded error', async () => {
    const issuer = createSigningIdentity(new Uint8Array(32).fill(7))
    const holder = createSigningIdentity(new Uint8Array(32).fill(8))
    const capability = await createCapability(issuer, {
      sub: issuer.id,
      aud: holder.id,
      act: 'write',
      res: 'doc/1',
      exp: now() + 3600,
      jti: 'grant-1',
    })
    const backend = createMemoryRevocationBackend()
    await backend.add(await createRevocationRecord(issuer, 'grant-1'))

    const error = await rejection(() =>
      createRevocationChecker(backend)(capability, stringifyToken(capability)),
    )
    expect(isTokenRevokedError(error)).toBe(true)
    expect(error).toBeInstanceOf(TokenRevokedError)
    expect((error as Error).message).toBe('Token revoked: grant-1')
    expect((error as Error).name).toBe('TokenRevokedError')
  })

  test('denied-key path: the refusal is branded and carries the resolution failure as cause', async () => {
    const seed = new Uint8Array(32).fill(53)
    const inception = createInception(seed, 0)
    const did = didFromInception(inception.event)
    const rotate = createRotate({ seed, profile: 0, did, prior: inception.event })
    const leaked = inception.event.k[0]
    if (leaked === undefined) throw new Error('expected inception key')
    const rotated: Array<SignedEvent> = [inception, rotate]
    const revoked: Array<SignedEvent> = [
      inception,
      rotate,
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: rotate.event,
        target: keyTarget(leaked),
        keyPosition: { gen: 0, seq: 1 },
      }),
    ]
    const registry = (log: Array<SignedEvent>): MethodRegistry => [
      createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) }),
    ]
    const thief = createControllerIdentity({ seed, profile: 0, log: [inception] })
    const owner = createControllerIdentity({ seed, profile: 0, log: revoked })
    const holder = createSigningIdentity(new Uint8Array(32).fill(61))

    const capability = await createCapability(owner, {
      sub: did,
      aud: holder.id,
      act: 'write',
      res: 'doc/1',
      exp: now() + 3600,
      jti: 'grant-1',
    })
    const backend = createMemoryRevocationBackend({ methods: registry(rotated) })
    await backend.add(await createRevocationRecord(thief, 'grant-1'))

    const error = await rejection(() =>
      createRevocationChecker(backend, { methods: registry(revoked) })(
        capability,
        stringifyToken(capability),
      ),
    )
    expect(isTokenRevokedError(error)).toBe(true)
    expect((error as Error).message).toBe('Token revoked: grant-1')
    expect((error as Error).cause).toBeDefined()
  })

  test('isTokenRevokedError does not match by message', () => {
    expect(isTokenRevokedError(new Error('Token revoked: x'))).toBe(false)
    expect(isTokenRevokedError('Token revoked: x')).toBe(false)
  })
})
