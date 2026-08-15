import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  keyTarget,
} from '@kokuin/controller'
import {
  createSigningIdentityForDID,
  type MethodRegistry,
  randomIdentity,
  randomPrivateKey,
  stringifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  checkCapability,
  createCapability,
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
  now,
} from '../src/index.js'

// Independent check of the key-revocation remedy, built without reference to the implementer's
// probes. Two questions: does denying a key actually stop it, and what does denying a key do to
// the revocation records that key had already signed?

const seed = new Uint8Array(32).fill(41)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const rotate = createRotate(seed, 0, did, inception.event)
const leakedKey = inception.event.k[0]

describe('key revocation, independently', () => {
  test('the denial stops the leaked key and leaves the live key working', async () => {
    const revoke = createRevoke(seed, 0, did, rotate.event, keyTarget(leakedKey), {
      gen: 0,
      seq: 1,
    })
    const denied: MethodRegistry = [
      createControllerResolver({
        loadLog: async (asked) => (asked === did ? [inception, rotate, revoke] : undefined),
      }),
    ]

    // Minted by the leaked key, before the denial existed.
    const thief = await randomIdentity()
    const stolenIdentity = createControllerIdentity(seed, 0, [inception])
    const stolen = stringifyToken(
      await createCapability(stolenIdentity, {
        sub: did,
        aud: thief.id,
        act: '*',
        res: '*',
        exp: now() + 3600,
      }),
    )

    let stolenRefusal = 'ACCEPTED'
    try {
      await checkCapability(
        { act: 'revoke', res: 'did:kokuin:zAnyone' },
        { iss: thief.id, sub: did, cap: [stolen] } as never,
        { methods: denied },
      )
    } catch (err) {
      stolenRefusal = (err as Error).message
    }
    console.log('stolen capability after key denial:', stolenRefusal)

    // CONTROL — the live key, same log, same shape. If this also fails the denial proves nothing.
    const owner = createControllerIdentity(seed, 0, [inception, rotate, revoke])
    const good = await randomIdentity()
    const honest = stringifyToken(
      await createCapability(owner, {
        sub: did,
        aud: good.id,
        act: '*',
        res: '*',
        exp: now() + 3600,
      }),
    )
    let honestRefusal = 'ACCEPTED'
    try {
      await checkCapability(
        { act: 'revoke', res: 'did:kokuin:zAnyone' },
        { iss: good.id, sub: did, cap: [honest] } as never,
        { methods: denied },
      )
    } catch (err) {
      honestRefusal = (err as Error).message
    }
    console.log('control — live key, same log:', honestRefusal)

    expect(stolenRefusal).not.toBe('ACCEPTED')
    expect(stolenRefusal).toContain('revoked')
    expect(honestRefusal).toBe('ACCEPTED')
  })

  test('what denying a key does to the revocation records it had already signed', async () => {
    // A profile that has NOT yet revoked its leaked key issues a capability and then revokes it
    // the ordinary way — a revocation record, signed by the key that is about to be denied.
    const before: MethodRegistry = [
      createControllerResolver({
        loadLog: async (asked) => (asked === did ? [inception, rotate] : undefined),
      }),
    ]
    const issuer = createControllerIdentity(seed, 0, [inception])
    const holder = await randomIdentity()
    const grant = stringifyToken(
      await createCapability(issuer, {
        sub: did,
        aud: holder.id,
        act: 'read',
        res: 'doc:A',
        exp: now() + 3600,
        jti: 'grant-1',
      } as never),
    )

    const backend = createMemoryRevocationBackend({ methods: before })
    await backend.add(await createRevocationRecord(issuer, 'grant-1'))
    const checker = createRevocationChecker(backend, { methods: before })

    const invoke = async (methods: MethodRegistry) => {
      try {
        await checkCapability(
          { act: 'read', res: 'doc:A' },
          { iss: holder.id, sub: did, cap: [grant] } as never,
          { methods, verifyToken: checker },
        )
        return 'ACCEPTED'
      } catch (err) {
        return (err as Error).message
      }
    }

    const beforeDenial = await invoke(before)
    console.log('revoked grant, before the key denial:', beforeDenial)

    const revoke = createRevoke(seed, 0, did, rotate.event, keyTarget(leakedKey), {
      gen: 0,
      seq: 1,
    })
    const after: MethodRegistry = [
      createControllerResolver({
        loadLog: async (asked) => (asked === did ? [inception, rotate, revoke] : undefined),
      }),
    ]
    const afterDenial = await invoke(after)
    console.log('revoked grant, after the key denial:', afterDenial)

    // The grant was revoked. Denying the key that signed the revocation record must not resurrect
    // it — and if it does, that is a fail-open worth stating out loud.
    expect(beforeDenial).not.toBe('ACCEPTED')
    expect(afterDenial).not.toBe('ACCEPTED')
  })

  test('a LIVE-key grant, revoked by a record the denied key signed', async () => {
    // The case the test above does not reach: the grant itself is signed by the key the profile
    // still holds, so the key denial cannot refuse it — and the only thing standing between the
    // holder and the grant is a revocation record signed by the key about to be denied.
    const before: MethodRegistry = [
      createControllerResolver({
        loadLog: async (asked) => (asked === did ? [inception, rotate] : undefined),
      }),
    ]
    const live = createControllerIdentity(seed, 0, [inception, rotate])
    const leaked = createControllerIdentity(seed, 0, [inception])
    const holder = await randomIdentity()
    const grant = stringifyToken(
      await createCapability(live, {
        sub: did,
        aud: holder.id,
        act: 'read',
        res: 'doc:B',
        exp: now() + 3600,
        jti: 'grant-2',
      } as never),
    )

    const backend = createMemoryRevocationBackend({ methods: before })
    // Signed by the key that is about to be denied. Same issuer DID either way.
    await backend.add(await createRevocationRecord(leaked, 'grant-2'))

    // The checker resolves through the SAME registry as the verification. A deployment whose
    // checker is pinned to a stale log would not see the denial at all, which is a different
    // question from the one being asked here.
    const invoke = async (methods: MethodRegistry) => {
      try {
        await checkCapability(
          { act: 'read', res: 'doc:B' },
          { iss: holder.id, sub: did, cap: [grant] } as never,
          { methods, verifyToken: createRevocationChecker(backend, { methods }) },
        )
        return 'ACCEPTED'
      } catch (err) {
        return (err as Error).message
      }
    }

    const beforeDenial = await invoke(before)
    console.log('LIVE-key grant, before the key denial:', beforeDenial)

    const revoke = createRevoke(seed, 0, did, rotate.event, keyTarget(leakedKey), {
      gen: 0,
      seq: 1,
    })
    const after: MethodRegistry = [
      createControllerResolver({
        loadLog: async (asked) => (asked === did ? [inception, rotate, revoke] : undefined),
      }),
    ]
    const afterDenial = await invoke(after)
    console.log('LIVE-key grant, after the key denial:', afterDenial)

    expect(beforeDenial).not.toBe('ACCEPTED')
    expect(afterDenial).not.toBe('ACCEPTED')
  })

  test('CONTROL — a record naming a key the log never published is still ignored', async () => {
    // The plant-a-record denial of service the swallow exists to stop. An untrusted backend hands
    // back a record signed by a key this DID never had, claiming to revoke a live grant. If
    // honouring denied-key records had widened into honouring unverifiable ones, this would deny.
    const revoke = createRevoke(seed, 0, did, rotate.event, keyTarget(leakedKey), {
      gen: 0,
      seq: 1,
    })
    const methods: MethodRegistry = [
      createControllerResolver({
        loadLog: async (asked) => (asked === did ? [inception, rotate, revoke] : undefined),
      }),
    ]

    const live = createControllerIdentity(seed, 0, [inception, rotate, revoke])
    const holder = await randomIdentity()
    const grant = stringifyToken(
      await createCapability(live, {
        sub: did,
        aud: holder.id,
        act: 'read',
        res: 'doc:C',
        exp: now() + 3600,
        jti: 'grant-3',
      } as never),
    )

    // Signed as the profile DID with a key the profile never published. A verifying backend would
    // refuse this on the way in, which is exactly why the checker cannot rely on one.
    const impostor = createSigningIdentityForDID(did, randomPrivateKey())
    const planted = await createRevocationRecord(impostor, 'grant-3')
    const untrusted = {
      add: async () => {},
      get: async (jti: string) => (jti === 'grant-3' ? planted : undefined),
    }

    let outcome = 'ACCEPTED'
    try {
      await checkCapability(
        { act: 'read', res: 'doc:C' },
        { iss: holder.id, sub: did, cap: [grant] } as never,
        { methods, verifyToken: createRevocationChecker(untrusted, { methods }) },
      )
    } catch (err) {
      outcome = (err as Error).message
    }
    console.log('planted record, key never published:', outcome)

    expect(outcome).toBe('ACCEPTED')
  })
})
