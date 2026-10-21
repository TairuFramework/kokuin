import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createReset,
  createRotate,
  didFromInception,
  foldLog,
  type SignedEvent,
  snapshotOf,
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
  checkCapability,
  createCapability,
  DEFAULT_MAX_DELEGATION_DEPTH,
  DENY_SET_UNAVAILABLE,
  now,
} from '../src/index.js'

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

// A deny entry naming a DID: "no capability whose `aud` is that DID is valid from this position
// onward." Everything here is real — a real inception, a real rotate whose snapshot denies the DID,
// signed by the profile's pre-committed key, a real `createCapability`, and a real delegate holding
// its own key. A stub deny set would agree with an implementation that enforces nothing, which is
// what this file exists to stop.

const seed = new Uint8Array(32).fill(31)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const controller = createControllerIdentity({ seed, profile: 0, log: [inception] })

const delegate = createSigningIdentity(new Uint8Array(32).fill(41))
const bystander = createSigningIdentity(new Uint8Array(32).fill(43))

/** The log the resolver folds, rebuilt per test. */
let log: Array<SignedEvent> = [inception]
const methods: MethodRegistry = [
  createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) }),
]

/** A rotate on `prior` whose snapshot is exactly `deny`, signed by the profile. */
function settle(prior: SignedEvent['event'], deny: Array<string>): SignedEvent {
  return createRotate({
    seed,
    profile: 0,
    did,
    prior,
    options: { snapshot: { members: [], deny } },
  })
}

/** A rotate denying `target`, chained onto the inception. */
function revokeOf(target: string): SignedEvent {
  return settle(inception.event, [target])
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
    // capability the moment a log carries any denial at all.
    const denied = await mintFor(delegate)
    const allowed = await mintFor(bystander)
    log = [inception, revokeOf(delegate.id)]

    await expect(invoke(delegate, denied)).rejects.toThrow(/audience is revoked/)
    await expect(invoke(bystander, allowed)).resolves.toBeUndefined()
  })

  test('the denial survives a rotation that carries the state forward', async () => {
    // A rotate's snapshot replaces the state, so routine key hygiene builds it from the fold's own
    // answer (`snapshotOf`) and must not quietly re-admit a revoked device.
    const cap = await mintFor(delegate)
    const revoke = revokeOf(delegate.id)
    const folded = foldLog(did, { chain: [inception, revoke], events: [] })
    if (!folded.ok) throw new Error('did not fold')
    log = [
      inception,
      revoke,
      createRotate({
        seed,
        profile: 0,
        did,
        prior: revoke.event,
        options: { snapshot: snapshotOf(at(folded.states, 1)) },
      }),
    ]

    await expect(invoke(delegate, cap)).rejects.toThrow(/audience is revoked/)
  })

  test('a snapshot leaving it out clears it', async () => {
    // `d` replaces the prior set rather than adding to it — the "cold rotate clearing the deny set"
    // the spec's remedy ladder names. A holder DID, unlike a retired key, may be dropped.
    const cap = await mintFor(delegate)
    const revoke = revokeOf(delegate.id)
    log = [inception, revoke, settle(revoke.event, [])]

    await expect(invoke(delegate, cap)).resolves.toBeUndefined()
  })

  test('a reset clears it, and the profile can grant the same device again', async () => {
    const revoke = revokeOf(delegate.id)
    const reset = createReset(seed, 0, 1)
    log = [inception, revoke, reset]

    // The capability has to be re-minted: a reset discards the prior generation, so one signed
    // under it no longer resolves at all. What this asserts is that the denial itself is gone.
    const regranted = await mintFor(delegate, createControllerIdentity({ seed, profile: 0, log }))
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
    // The self-issued branch of `checkCapability`: the capability's own `iss` is its `sub`, so
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

  test('a delegated one is rejected once its own audience is revoked', async () => {
    // The delegated branch, where the chain walk starts at the *parent*: only the presented
    // capability's own audience check catches this, because `delegate` appears nowhere above it.
    const manager = randomIdentity()
    const rootRaw = stringifyToken(
      await createCapability(
        controller,
        { sub: did, aud: manager.id, act: 'revoke', res: '*', exp: now() + 3600 },
        undefined,
        { methods },
      ),
    )
    const leaf = await createCapability(
      manager,
      { sub: did, aud: delegate.id, act: 'revoke', res: '*', exp: now() + 3600, cap: [rootRaw] },
      undefined,
      { parentCapability: rootRaw, methods },
    )

    // Control: nobody revoked, and the same presented capability authorises.
    await expect(
      checkCapability({ act: 'revoke', res: 'doc/1' }, leaf.payload, { methods }),
    ).resolves.toBeUndefined()

    // Control: revoking the *manager* — the audience the chain walk does reach — is refused, so
    // the deny set is live for this capability whichever link carries the revoked audience.
    log = [inception, revokeOf(manager.id)]
    await expect(
      checkCapability({ act: 'revoke', res: 'doc/1' }, leaf.payload, { methods }),
    ).rejects.toThrow(`Invalid capability: audience is revoked by the subject: ${manager.id}`)

    log = [inception, revokeOf(delegate.id)]
    await expect(
      checkCapability({ act: 'revoke', res: 'doc/1' }, leaf.payload, { methods }),
    ).rejects.toThrow(`Invalid capability: audience is revoked by the subject: ${delegate.id}`)
  })

  test('a delegated one grants only what it names, not what its parent named', async () => {
    // The parent grants `revoke *`; the leaf narrows to `doc/1`. Presenting the leaf for anything
    // else has to fail on the leaf's own `res`, since the parent covers it.
    const manager = randomIdentity()
    const rootRaw = stringifyToken(
      await createCapability(
        controller,
        { sub: did, aud: manager.id, act: 'revoke', res: '*', exp: now() + 3600 },
        undefined,
        { methods },
      ),
    )
    const leaf = await createCapability(
      manager,
      {
        sub: did,
        aud: delegate.id,
        act: 'revoke',
        res: 'doc/1',
        exp: now() + 3600,
        cap: [rootRaw],
      },
      undefined,
      { parentCapability: rootRaw, methods },
    )

    await expect(
      checkCapability({ act: 'revoke', res: 'doc/1' }, leaf.payload, { methods }),
    ).resolves.toBeUndefined()
    await expect(
      checkCapability({ act: 'revoke', res: 'doc/2' }, leaf.payload, { methods }),
    ).rejects.toThrow('Invalid capability: permission not granted')
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
      // Forwarded like the rest: a capability is archived material, so `verifyToken` asks this
      // member for it, and a wrapper omitting it makes every capability unverifiable rather than
      // isolating the thing under test.
      resolveHistoric: (asked, header) => inner.resolveHistoric?.(asked, header) as never,
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
      // Forwarded, so the *only* member this wrapper drops is `resolveDenySet` — otherwise the
      // capability would be refused for want of a historic answer and the deny rule would never be
      // reached, certifying a check that never ran.
      resolveHistoric: (asked, header) => real.resolveHistoric?.(asked, header) as never,
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
    expect((await at(methods, 0).resolveDenySet?.(did))?.has(device.id)).toBe(true)

    const token = await signToken(device, createUnsignedToken({ hello: 'world' }))
    await expect(verifyToken(stringifyToken(token), { methods })).resolves.toMatchObject({
      payload: { iss: device.id },
    })
  })
})

describe('the deny set the resolver exposes', () => {
  test('is the head state: the latest snapshot, not an accumulation', async () => {
    const first = revokeOf(delegate.id)
    const second = settle(first.event, [bystander.id])
    log = [inception, first, second]

    const denied = await at(methods, 0).resolveDenySet?.(did)
    expect(denied).toBeDefined()
    expect([...(denied ?? [])]).toEqual([bystander.id])
  })

  test('is empty for a log that revokes nothing', async () => {
    expect([...((await at(methods, 0).resolveDenySet?.(did)) ?? [])]).toEqual([])
  })

  test('rejects an unknown DID rather than answering with an empty set', async () => {
    // Fail closed: an empty answer for a DID nothing could load would read as "nobody is revoked".
    await expect(at(methods, 0).resolveDenySet?.('did:kokuin:zNope')).rejects.toThrow(/Unknown DID/)
  })
})

describe('a deny set nothing could answer for', () => {
  // The rule was silent when no registry was supplied at all, justified by "a subject that needs one
  // is a subject `verifyToken` could not have resolved either". True for a chain, whose root link is
  // issued by the subject. Not true for the `iss === sub` arm of `checkCapability`, which takes a
  // payload the caller verified: a caller who resolved the profile with their own resolver and then
  // omitted `methods` here got no enforcement, and nothing said so.

  test('a did:kokuin subject with no registry is refused rather than waved through', async () => {
    log = [inception, revokeOf(delegate.id)]
    const payload = {
      iss: did,
      sub: did,
      aud: delegate.id,
      act: 'write',
      res: 'doc/1',
      exp: now() + 3600,
    }

    // CONTROL — with the registry, the denial is what decides.
    await expect(
      checkCapability({ act: 'write', res: 'doc/1' }, payload, { methods }),
    ).rejects.toThrow(/audience is revoked/)

    // The same call with the registry omitted. It used to resolve.
    await expect(checkCapability({ act: 'write', res: 'doc/1' }, payload)).rejects.toThrow(
      DENY_SET_UNAVAILABLE,
    )
  })

  test('CONTROL — a subject that carries its own keys needs no registry', async () => {
    // `did:key` and `did:peer` have no deny set to miss, so requiring a registry for them would be a
    // false positive on the ordinary case that has nothing to do with controllers.
    const selfIssued = randomIdentity()
    await expect(
      checkCapability(
        { act: 'write', res: 'doc/1' },
        {
          iss: selfIssued.id,
          sub: selfIssued.id,
          aud: delegate.id,
          act: 'write',
          res: 'doc/1',
          exp: now() + 3600,
        },
      ),
    ).resolves.toBeUndefined()
  })
})
