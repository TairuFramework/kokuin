import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createReset,
  createRevoke,
  createRevokeWithKey,
  createRotate,
  didFromInception,
  foldLogAsync,
  type SignedEvent,
} from '@kokuin/controller'
import {
  createIdentity,
  createSigningIdentity,
  createUnsignedToken,
  type DIDMethodResolver,
  type MethodRegistry,
  randomIdentity,
  type SigningIdentity,
  signToken,
  stringifyToken,
  verifyToken,
} from '@kokuin/token'
import { beforeEach, describe, expect, test } from 'vitest'

import {
  audienceConfirmation,
  checkCapability,
  createCapability,
  createControllerCapabilityVerifier,
  DEFAULT_MAX_DELEGATION_DEPTH,
  now,
  REVOKE_NO_POSITION,
} from '../src/index.js'

// The spec's definition of `revoke`: "Adds a DID to the profile's deny set: no capability whose
// `aud` is that DID is valid from this position onward." Everything here is real — a real inception,
// a real revoke signed by the profile's authority key, a real `createCapability`, and a real
// delegate holding its own key. A stub deny set would agree with an implementation that enforces
// nothing, which is what this file exists to stop.

const seed = new Uint8Array(32).fill(31)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const controller = createControllerIdentity(seed, 0, [inception])

/** The authority key the inception establishes lives at gen 0 / seq 0. */
const inceptionKeyPosition = { gen: 0, seq: 0 }

const delegate = createSigningIdentity(new Uint8Array(32).fill(41))
const bystander = createSigningIdentity(new Uint8Array(32).fill(43))

/** The log the resolver folds, rebuilt per test. */
let log: Array<SignedEvent> = [inception]
const methods: MethodRegistry = [
  createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) }),
]

/** A revoke denying `target`, chained onto the inception and signed by the profile. */
function revokeOf(target: string): SignedEvent {
  return createRevoke(seed, 0, did, inception.event, target, inceptionKeyPosition)
}

async function mintFor(audience: SigningIdentity, signer = controller): Promise<string> {
  const capability = await createCapability(
    signer,
    {
      sub: did,
      aud: audience.id,
      act: 'write',
      res: 'doc/1',
      exp: now() + 3600,
    },
    undefined,
    { methods },
  )
  return stringifyToken(capability)
}

/** Invoke `chain` as its audience would: the holder presents it as its own `cap` chain. */
async function invoke(holder: SigningIdentity, ...chain: Array<string>): Promise<void> {
  await checkCapability(
    { act: 'write', res: 'doc/1' },
    { iss: holder.id, sub: did, cap: chain },
    { methods },
  )
}

const deviceX = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const deviceY = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'

/** The management capability: revoke anything, pinned to `holder`'s key. */
async function manageCap(holder: { id: string; publicKey: Uint8Array }): Promise<string> {
  const capability = await createCapability(
    controller,
    {
      sub: did,
      aud: holder.id,
      act: 'revoke',
      res: '*',
      exp: now() + 3600,
      cnf: audienceConfirmation({ alg: 'EdDSA', publicKey: holder.publicKey }),
    },
    undefined,
    { methods },
  )
  return stringifyToken(capability)
}

/** A registry answering with a fixed log, whatever the fold is doing. */
function registryFor(fixed: Array<SignedEvent>): MethodRegistry {
  return [
    createControllerResolver({ loadLog: async (asked) => (asked === did ? fixed : undefined) }),
  ]
}

beforeEach(() => {
  log = [inception]
})

describe('a capability whose audience the profile has revoked', () => {
  test('verifies before the revoke and is rejected after it', async () => {
    const cap = await mintFor(delegate)
    await expect(invoke(delegate, cap)).resolves.toBeUndefined()

    log = [inception, revokeOf(delegate.id)]
    await expect(invoke(delegate, cap)).rejects.toThrow(
      `Invalid capability: audience is revoked by the subject: ${delegate.id}`,
    )
  })

  test('a capability to an audience that was not revoked still verifies', async () => {
    // The control row. Without it this file passes against an implementation that rejects every
    // capability the moment a log carries any revoke at all.
    const denied = await mintFor(delegate)
    const allowed = await mintFor(bystander)
    log = [inception, revokeOf(delegate.id)]

    await expect(invoke(delegate, denied)).rejects.toThrow(/audience is revoked/)
    await expect(invoke(bystander, allowed)).resolves.toBeUndefined()
  })

  test('the denial survives a rotation', async () => {
    // A rotate carries the accumulated deny set forward unless it publishes a snapshot, so routine
    // key hygiene must not quietly re-admit a revoked device.
    const cap = await mintFor(delegate)
    const revoke = revokeOf(delegate.id)
    log = [
      inception,
      revoke,
      createRotate(seed, 0, did, revoke.event, { keyPosition: inceptionKeyPosition }),
    ]

    await expect(invoke(delegate, cap)).rejects.toThrow(/audience is revoked/)
  })

  test('a deny-set snapshot clears it', async () => {
    // `d` replaces the accumulated set rather than adding to it — the "cold rotate clearing the
    // deny set" the spec's remedy ladder names.
    const cap = await mintFor(delegate)
    const revoke = revokeOf(delegate.id)
    log = [
      inception,
      revoke,
      createRotate(seed, 0, did, revoke.event, { keyPosition: inceptionKeyPosition, deny: [] }),
    ]

    await expect(invoke(delegate, cap)).resolves.toBeUndefined()
  })

  test('a reset clears it, and the profile can grant the same device again', async () => {
    const revoke = revokeOf(delegate.id)
    const reset = createReset(seed, 0, 1)
    log = [inception, revoke, reset]

    // The capability has to be re-minted: a reset discards the prior generation, so one signed
    // under it no longer resolves at all. What this asserts is that the denial itself is gone.
    const regranted = await mintFor(delegate, createControllerIdentity(seed, 0, log))
    await expect(invoke(delegate, regranted)).resolves.toBeUndefined()
  })

  test('the denial applies at the head, not at the position the capability names', async () => {
    // `iat` is author-supplied and backdatable, so anchoring the check to anything the token
    // carries would let the holder choose a position where it was not yet denied.
    const backdated = await createCapability(
      controller,
      {
        sub: did,
        aud: delegate.id,
        act: 'write',
        res: 'doc/1',
        iat: now() - 3600,
        exp: now() + 3600,
      },
      undefined,
      { methods },
    )
    log = [inception, revokeOf(delegate.id)]

    await expect(invoke(delegate, stringifyToken(backdated))).rejects.toThrow(/audience is revoked/)
  })

  test('a did:peer:4 audience is denied under either spelling of its DID', async () => {
    // A `rev` writes whatever DID string the profile had, and a capability's `aud` may carry the
    // other form. Matching only one spelling would let a revoked device keep its grant by
    // presenting the form the log does not name.
    const peer = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    expect(peer.longForm).not.toBe(peer.id)

    const capability = await createCapability(
      controller,
      { sub: did, aud: peer.longForm, act: 'write', res: 'doc/1', exp: now() + 3600 },
      undefined,
      { methods },
    )
    const cap = stringifyToken(capability)
    const holder = { id: peer.longForm } as SigningIdentity

    // Control: unrevoked, the long-form audience verifies.
    await expect(invoke(holder, cap)).resolves.toBeUndefined()

    // Revoked by short form, granted to the long form.
    log = [inception, revokeOf(peer.id)]
    await expect(invoke(holder, cap)).rejects.toThrow(/audience is revoked/)

    // Revoked by the very string the capability names.
    log = [inception, revokeOf(peer.longForm)]
    await expect(invoke(holder, cap)).rejects.toThrow(/audience is revoked/)
  })
})

describe('a payload whose `sub` or `aud` is not a string', () => {
  test('is answered rather than crashing the deny check', async () => {
    // `checkCapability` takes a `SignedPayload` and nothing upstream types its members: `verifyToken`
    // does not require `sub` or `aud` to be strings, so a token carrying `"sub": 42` verifies and
    // arrives here. A deny set holds strings, so neither member has anything to look up — but
    // without the type guard the lookup runs anyway, and `findMethodResolver` splits `sub` on `:`.
    // That is a `TypeError` out of a function whose only failure mode is supposed to be a denial.
    log = [inception, revokeOf(delegate.id)]
    const base = { act: 'write', res: 'doc/1' }

    for (const payload of [
      { iss: 42, sub: 42, aud: delegate.id, ...base },
      { iss: did, sub: did, aud: 42, ...base },
    ]) {
      await expect(
        checkCapability(base, payload as never, { methods }),
        JSON.stringify(payload),
      ).resolves.toBeUndefined()
    }

    // Control: the same payload with both members as strings, naming a revoked audience, is denied
    // — so the rows above are the type guard and not a deny set that is never consulted.
    await expect(
      checkCapability(base, { iss: did, sub: did, aud: delegate.id, ...base } as never, {
        methods,
      }),
    ).rejects.toThrow(/audience is revoked/)
  })
})

describe('a revoked link in a delegation chain', () => {
  test('denies the leaf even when the leaf audience is not revoked', async () => {
    // controller → manager → delegate, with the *manager* revoked. Only a check that walks every
    // link catches this: the leaf's own audience is untouched.
    const manager = randomIdentity()
    const root = await createCapability(
      controller,
      { sub: did, aud: manager.id, act: 'write', res: '*', exp: now() + 3600 },
      undefined,
      { methods },
    )
    const rootRaw = stringifyToken(root)
    const leaf = await createCapability(
      manager,
      { sub: did, aud: delegate.id, act: 'write', res: 'doc/1', exp: now() + 3600, cap: [rootRaw] },
      undefined,
      { parentCapability: rootRaw, methods },
    )
    const leafRaw = stringifyToken(leaf)

    // Control: the whole chain verifies while nobody is revoked.
    await expect(invoke(delegate, leafRaw, rootRaw)).resolves.toBeUndefined()

    log = [inception, revokeOf(manager.id)]
    await expect(invoke(delegate, leafRaw, rootRaw)).rejects.toThrow(
      `Invalid capability: audience is revoked by the subject: ${manager.id}`,
    )
  })
})

describe('a capability presented directly, without an invocation', () => {
  test('is rejected once its audience is revoked', async () => {
    // The self-issued branch of `checkCapability`, which is the shape
    // `createControllerCapabilityVerifier` takes: the capability's own `iss` is its `sub`, so
    // there is no chain to walk and the audience check has to happen on this path too.
    const cap = await createCapability(
      controller,
      { sub: did, aud: delegate.id, act: 'revoke', res: '*', exp: now() + 3600 },
      undefined,
      { methods },
    )

    await expect(
      checkCapability({ act: 'revoke', res: 'doc/1' }, cap.payload, { methods }),
    ).resolves.toBeUndefined()

    log = [inception, revokeOf(delegate.id)]
    await expect(
      checkCapability({ act: 'revoke', res: 'doc/1' }, cap.payload, { methods }),
    ).rejects.toThrow(/audience is revoked/)
  })
})

describe('the deny set inside the fold: who may author a capability-authorised revoke', () => {
  // The management tier of the spec's authority ladder: a device holding a capability whose `act`
  // is `revoke` authors `rev` events for the profile. What stops a revoked manager from carrying on
  // is the deny set at the position of its own event — which nothing outside the fold can name, so
  // the fold hands the verifier a resolver for exactly that position.

  test('a revoked manager cannot author one — at every prefix a caller could supply', async () => {
    const manager = randomIdentity()
    const cap = await manageCap(manager)
    const revokeManager = revokeOf(manager.id)
    const attack = createRevokeWithKey(manager.privateKey, did, revokeManager.event, deviceX, {
      cap,
    })
    const attacked = [inception, revokeManager, attack]
    const rejected = {
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 2,
    }

    // The caller's registry decides nothing here, which is the fix: the fold resolves the subject
    // from its own prefix. Both answers a `loadLog(did)` could give — and no registry at all — are
    // the same rejection.
    for (const [name, configured] of [
      ['no registry', undefined],
      ['the earliest prefix', registryFor([inception])],
      ['the prefix before the attack', registryFor([inception, revokeManager])],
      ['the whole log', registryFor(attacked)],
    ] as Array<[string, MethodRegistry | undefined]>) {
      const result = await foldLogAsync(did, attacked, {
        verifyCapability: createControllerCapabilityVerifier({ methods: configured }),
      })
      expect(result, name).toEqual(rejected)
    }

    // Control: the same manager, the same capability, the same revoke of X — with the manager not
    // revoked. So what fails above is the denial and not the grant.
    const clean = createRevokeWithKey(manager.privateKey, did, inception.event, deviceX, { cap })
    const folded = await foldLogAsync(did, [inception, clean], {
      verifyCapability: createControllerCapabilityVerifier(),
    })
    expect(folded.ok).toBe(true)
    if (!folded.ok) return
    expect(folded.states[1].deny.has(deviceX)).toBe(true)
  })

  test('two capability-authorised revokes in one log fold through one ordinary resolver', async () => {
    // The shape that had no working wiring: with a single `loadLog(did)` and two events asking, the
    // only prefix that keeps the profile resolvable is the earliest one — which is precisely the
    // prefix at which the row above is bypassed. Nothing here is hand-nested: one resolver, one
    // `loadLog` answering with the whole log, one verifier.
    const manager = randomIdentity()
    const cap = await manageCap(manager)
    const first = createRevokeWithKey(manager.privateKey, did, inception.event, deviceX, { cap })
    const second = createRevokeWithKey(manager.privateKey, did, first.event, deviceY, { cap })
    log = [inception, first, second]

    const resolver = createControllerResolver({
      loadLog: async (asked) => (asked === did ? log : undefined),
      verifyCapability: createControllerCapabilityVerifier(),
    })
    expect([...((await resolver.resolveDenySet?.(did)) ?? [])].sort()).toEqual(
      [deviceX, deviceY].sort(),
    )
    // And the profile still resolves, which is the half a wedged instance loses.
    await expect(resolver.resolve(did, {})).resolves.toMatchObject({ alg: 'EdDSA' })

    // A third revoke, of the manager, and the manager's own next attempt after it.
    const third = revokeOf(manager.id)
    expect(
      await foldLogAsync(did, [inception, third], {
        verifyCapability: createControllerCapabilityVerifier(),
      }),
    ).toMatchObject({ ok: true })
  })

  test('a verifier called without the position refuses, whatever the caller configured', async () => {
    // The three-argument call: an older `@kokuin/controller` whose `foldLogAsync` predates the
    // fourth argument, or a caller invoking the verifier directly. `@kokuin/capability` has no
    // runtime dependency on the controller, so nothing ties the two versions together and the type
    // cannot police the call. Falling back to the caller's registry — which is what this did — is
    // the R-2 bypass verbatim: with a registry answering the earliest prefix, a manager the log
    // revoked at event 1 was authorised to revoke `deviceX` at event 2.
    const manager = randomIdentity()
    const cap = await manageCap(manager)
    const revokeManager = revokeOf(manager.id)

    for (const [name, configured] of [
      ['the earliest prefix', registryFor([inception])],
      ['the whole log', registryFor([inception, revokeManager])],
      ['no registry', undefined],
    ] as Array<[string, MethodRegistry | undefined]>) {
      const verify = createControllerCapabilityVerifier({ methods: configured })
      const threeArgs = verify as unknown as (
        cap: string,
        subject: string,
        target: string,
      ) => Promise<unknown>
      await expect(threeArgs(cap, did, deviceX), name).resolves.toEqual({
        authorised: false,
        reason: REVOKE_NO_POSITION,
      })
    }

    // Unconditional rather than a denial that happens to coincide with this manager's revocation:
    // the same capability, held by a manager nothing has revoked, refuses the same way through the
    // three-argument call and folds through the four-argument one.
    const clean = createRevokeWithKey(manager.privateKey, did, inception.event, deviceX, { cap })
    const verify = createControllerCapabilityVerifier()
    const threeArgs = verify as unknown as (
      cap: string,
      subject: string,
      target: string,
    ) => Promise<unknown>
    await expect(threeArgs(cap, did, deviceX)).resolves.toEqual({
      authorised: false,
      reason: REVOKE_NO_POSITION,
    })
    await expect(
      foldLogAsync(did, [inception, clean], { verifyCapability: verify }),
    ).resolves.toMatchObject({ ok: true })
  })

  test('a capability minted for one profile cannot revoke on another', async () => {
    // The subject binding, re-checked now that the registry the verifier uses is assembled rather
    // than supplied: the fold's resolver answers for its own profile only.
    const otherSeed = new Uint8Array(32).fill(61)
    const otherInception = createInception(otherSeed, 0)
    const otherDid = didFromInception(otherInception.event)
    const manager = randomIdentity()
    const foreign = await createCapability(
      createControllerIdentity(otherSeed, 0, [otherInception]),
      {
        sub: otherDid,
        aud: manager.id,
        act: 'revoke',
        res: '*',
        exp: now() + 3600,
        cnf: audienceConfirmation({ alg: 'EdDSA', publicKey: manager.publicKey }),
      },
      undefined,
      { methods: registryFor([otherInception]) },
    )
    const revoke = createRevokeWithKey(manager.privateKey, did, inception.event, deviceX, {
      cap: stringifyToken(foreign),
    })

    await expect(
      foldLogAsync(did, [inception, revoke], {
        verifyCapability: createControllerCapabilityVerifier({
          methods: [
            createControllerResolver({
              loadLog: async (asked) => (asked === otherDid ? [otherInception] : undefined),
            }),
          ],
        }),
      }),
    ).resolves.toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })
})

describe('what the deny lookup costs a caller-supplied chain', () => {
  test('an over-long chain throws the depth error before any deny set is folded', async () => {
    // The lookup folds a log, so it has to sit *after* the depth bound: otherwise the length of an
    // attacker-supplied `cap` array decides how much log-folding a verifier does before rejecting
    // it. Exactly zero, not "at most maxDepth" — moving the lookup back above the bound yields one
    // call, which every looser assertion admits.
    let denyCalls = 0
    const inner = createControllerResolver({ loadLog: async (asked) => (asked === did ? log : []) })
    const counting: DIDMethodResolver = {
      method: 'kokuin',
      resolve: (asked, header) => inner.resolve(asked, header),
      resolveDenySet: async (asked) => {
        denyCalls++
        return (await inner.resolveDenySet?.(asked)) ?? new Set<string>()
      },
    }
    const cap = await mintFor(delegate)
    const overlong = Array.from({ length: DEFAULT_MAX_DELEGATION_DEPTH + 40 }, () => 'not.a.token')

    await expect(
      checkCapability(
        { act: 'write', res: 'doc/1' },
        { iss: delegate.id, sub: did, cap: [cap, ...overlong] },
        { methods: [counting] },
      ),
    ).rejects.toThrow(/exceeds maximum depth/)
    expect(denyCalls).toBe(0)

    // Control: the same registry does get asked when the chain is within the bound, so the zero
    // above is the ordering and not a resolver that is never consulted.
    await expect(
      checkCapability(
        { act: 'write', res: 'doc/1' },
        { iss: delegate.id, sub: did, cap: [cap] },
        { methods: [counting] },
      ),
    ).resolves.toBeUndefined()
    expect(denyCalls).toBeGreaterThan(0)
  })
})

describe('accepted limits, pinned so that changing them has to be deliberate', () => {
  test('a resolver that omits the optional `resolveDenySet` disables the rule', async () => {
    // `resolveDenySet` is optional on `DIDMethodResolver`, and the plausible way to lose it is a
    // wrapper — caching, metrics, tracing — around the one member its author knows about. Both
    // calls below use the same revoked delegate and the same capability; only the registry differs.
    // Making the member required would break every implementation of a published interface, so the
    // obligation is documented (`method.ts`, `capability.skill.md`) rather than enforced.
    log = [inception, revokeOf(delegate.id)]
    const real = createControllerResolver({ loadLog: async (asked) => (asked === did ? log : []) })
    const wrapped: DIDMethodResolver = {
      method: 'kokuin',
      resolve: (asked, header) => real.resolve(asked, header),
    }
    const cap = await mintFor(delegate)
    const invocation = { iss: delegate.id, sub: did, cap: [cap] }

    await expect(
      checkCapability({ act: 'write', res: 'doc/1' }, invocation, { methods: [real] }),
    ).rejects.toThrow(/audience is revoked/)
    await expect(
      checkCapability({ act: 'write', res: 'doc/1' }, invocation, { methods: [wrapped] }),
    ).resolves.toBeUndefined()
  })

  test('a revoked device`s own plain token still verifies', async () => {
    // The deny set answers "no capability whose `aud` is that DID is valid", which is what the spec
    // says and all that is implemented. A plain token names no subject, so `verifyToken` has no
    // `sub` to look a deny set up by — this cannot be closed inside `verifyToken` even in
    // principle. A consumer authenticating a device by bare token gets no denial from a revoke.
    const device = randomIdentity()
    log = [inception, revokeOf(device.id)]
    expect((await methods[0].resolveDenySet?.(did))?.has(device.id)).toBe(true)

    const token = await signToken(device, createUnsignedToken({ hello: 'world' }))
    await expect(verifyToken(stringifyToken(token), { methods })).resolves.toMatchObject({
      payload: { iss: device.id },
    })
  })

  test('a verifyToken hook that resolves this profile through this resolver wedges it', async () => {
    // The one re-entry the R-2 fix does not remove. The fold no longer resolves the DID it is
    // folding, so the hazard is now entirely in caller code — a revocation checker built over the
    // same registry is the realistic shape — and it is a *quiet* deadlock rather than a spin: the
    // hook joins the in-flight fold, which is waiting on the hook. Diagnosing it from inside would
    // need chain identity across three packages, so it is documented
    // (`ControllerResolverOptions.loadLog`, `auth.skill.md`) and pinned here.
    const manager = randomIdentity()
    const cap = await manageCap(manager)
    log = [
      inception,
      createRevokeWithKey(manager.privateKey, did, inception.event, deviceX, { cap }),
    ]

    let hookCalls = 0
    let wedged: DIDMethodResolver | undefined
    wedged = createControllerResolver({
      loadLog: async (asked) => (asked === did ? log : undefined),
      verifyCapability: createControllerCapabilityVerifier({
        verifyToken: async () => {
          hookCalls++
          // Re-entry: the profile this hook is being called *inside* the fold of.
          await wedged?.resolve(did, {})
        },
      }),
    })

    const timeout = (label: string) =>
      new Promise<string>((resolve) => setTimeout(() => resolve(label), 150))
    expect(
      await Promise.race([wedged.resolve(did, {}).then(() => 'settled'), timeout('wedged')]),
    ).toBe('wedged')
    expect(hookCalls).toBe(1)
    // The instance is finished for that DID: a second resolution joins the fold that cannot settle,
    // without calling `loadLog` or the hook again.
    expect(
      await Promise.race([wedged.resolve(did, {}).then(() => 'settled'), timeout('wedged')]),
    ).toBe('wedged')
    expect(hookCalls).toBe(1)
    // The timer queue stayed live throughout — that is what makes a caller-side timeout the
    // remedy — and the documented fix works: a hook with a resolver of its own settles.
    const own = createControllerResolver({ loadLog: async () => [inception] })
    const fine = createControllerResolver({
      loadLog: async (asked) => (asked === did ? log : undefined),
      verifyCapability: createControllerCapabilityVerifier({
        verifyToken: async () => {
          await own.resolve(did, {})
        },
      }),
    })
    expect(
      await Promise.race([fine.resolve(did, {}).then(() => 'settled'), timeout('wedged')]),
    ).toBe('settled')
  })
})

describe('the deny set the resolver exposes', () => {
  test('is the head state, and carries every revoke in the current generation', async () => {
    const first = revokeOf(delegate.id)
    const second = createRevoke(seed, 0, did, first.event, bystander.id, inceptionKeyPosition)
    log = [inception, first, second]

    const denied = await methods[0].resolveDenySet?.(did)
    expect(denied).toBeDefined()
    expect([...(denied ?? [])].sort()).toEqual([delegate.id, bystander.id].sort())
  })

  test('is empty for a log that revokes nothing', async () => {
    expect([...((await methods[0].resolveDenySet?.(did)) ?? [])]).toEqual([])
  })

  test('rejects an unknown DID rather than answering with an empty set', async () => {
    // Fail closed: an empty answer for a DID nothing could load would read as "nobody is revoked".
    await expect(methods[0].resolveDenySet?.('did:kokuin:zNope')).rejects.toThrow(/Unknown DID/)
  })
})
