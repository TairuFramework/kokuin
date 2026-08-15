import {
  authorityPath,
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRevokeWithKey,
  createRotate,
  deriveKeyPair,
  didFromInception,
  encodeKey,
  type FoldResult,
  foldLogAsync,
  type InceptionEvent,
  type SignedEvent,
} from '@kokuin/controller'
import {
  createIdentity,
  createSigningIdentity,
  type MethodRegistry,
  randomIdentity,
  type SigningIdentity,
  stringifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  assertRevokeCapabilityAudience,
  audienceConfirmation,
  type ConfirmationClaim,
  createCapability,
  createControllerCapabilityVerifier,
  now,
  REVOKE_AUDIENCE_KEY_MISMATCH,
  REVOKE_NO_AUDIENCE_KEY,
  REVOKE_UNBOUNDED_LIFETIME,
} from '../src/index.js'

// Every object on this path is real: a real inception, a real `createCapability`, a real revoke
// event signed by the delegate's own key, folded by the real `foldLogAsync`. A stub
// `verifyCapability` agrees with a broken adapter, which is exactly what this file exists to stop.

const controllerSeed = new Uint8Array(32).fill(3)
const otherControllerSeed = new Uint8Array(32).fill(5)
const delegateSeed = new Uint8Array(32).fill(11)
const outsiderSeed = new Uint8Array(32).fill(13)

/** The device being denied, and one that is not. */
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const bystander = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'

/** The authority key the inception establishes lives at gen 0 / seq 0. */
const inceptionKeyPosition = { gen: 0, seq: 0 }

/**
 * A signing identity for a seed, using the same derivation `createRevoke` uses for its signature.
 * That is what makes the delegate's `did:key` and the key that signs the revoke the same key.
 */
function identityForSeed(seed: Uint8Array): SigningIdentity {
  return createSigningIdentity(deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').privateKey)
}

/** The public key `createRevoke(seed, …)` signs with — what a capability pins as its audience key. */
function confirmationForSeed(seed: Uint8Array): ConfirmationClaim {
  return audienceConfirmation({
    alg: 'EdDSA',
    publicKey: deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
  })
}

const delegate = identityForSeed(delegateSeed)
const outsider = identityForSeed(outsiderSeed)

type Controller = {
  did: string
  inception: SignedEvent<InceptionEvent>
  identity: SigningIdentity
  seed: Uint8Array
}

function buildController(seed: Uint8Array): Controller {
  const inception = createInception(seed, 0)
  const did = didFromInception(inception.event)
  return { did, inception, identity: createControllerIdentity(seed, 0, [inception]), seed }
}

const controller = buildController(controllerSeed)
const otherController = buildController(otherControllerSeed)

/**
 * A registry resolving both controllers from the state their inception establishes.
 *
 * Deliberately *not* the same `loadLog` the fold is running over. The capability is issued by the
 * controller whose log contains the revoke, so a registry that loaded the full log would resolve
 * the issuer by folding it, which would reach the same capability-authorised revoke and call the
 * verifier again — unbounded recursion. A capability must in any case be checked against the key
 * state at the position *before* the event that carries it, which is what the prefix here is.
 */
const methods: MethodRegistry = [
  createControllerResolver({
    loadLog: async (did) => {
      if (did === controller.did) return [controller.inception]
      if (did === otherController.did) return [otherController.inception]
      return undefined
    },
  }),
]

type CapabilityFields = {
  issuer?: Controller
  signer?: SigningIdentity
  sub?: string
  aud?: string
  act?: string | Array<string>
  res?: string | Array<string>
  /** Explicit `undefined` mints a capability that never expires — not the same as omitting it. */
  exp?: number | undefined
  /** Explicit `undefined` mints a capability with no pin at all — not the same as omitting it. */
  cnf?: ConfirmationClaim | undefined
  /** The parent chain carried in the payload, which is where `checkCapability` walks it from. */
  cap?: Array<string>
  parentCapability?: string
}

async function mintCapability(fields: CapabilityFields = {}): Promise<string> {
  const issuer = fields.issuer ?? controller
  const capability = await createCapability(
    fields.signer ?? issuer.identity,
    {
      sub: fields.sub ?? issuer.did,
      aud: fields.aud ?? delegate.id,
      act: fields.act ?? 'revoke',
      res: fields.res ?? target,
      exp: 'exp' in fields ? fields.exp : now() + 3600,
      cnf: 'cnf' in fields ? fields.cnf : confirmationForSeed(delegateSeed),
      cap: fields.cap,
    },
    undefined,
    { parentCapability: fields.parentCapability, methods },
  )
  return stringifyToken(capability)
}

/**
 * Fold `[inception, revoke]` for the controller, with the revoke authorised by `cap` and signed by
 * `signerSeed` — the delegate's seed unless a test is exercising the audience binding.
 */
async function foldWithCapability(
  cap: string,
  options: { signerSeed?: Uint8Array; deny?: string } = {},
): Promise<FoldResult> {
  const revoke = createRevoke(
    options.signerSeed ?? delegateSeed,
    0,
    controller.did,
    controller.inception.event,
    options.deny ?? target,
    inceptionKeyPosition,
    { cap },
  )
  return await foldLogAsync(controller.did, [controller.inception, revoke], {
    verifyCapability: createControllerCapabilityVerifier({ methods }),
  })
}

describe('createControllerCapabilityVerifier()', () => {
  test('a real capability authorises a real revoke through the fold', async () => {
    const result = await foldWithCapability(await mintCapability())

    expect(result.ok).toBe(true)
    if (!result.ok) return
    // The state after the revoke — position 1 — is where the deny takes effect.
    expect(result.states[1].deny.has(target)).toBe(true)
    // Position-dependence: the inception's state never learns about it.
    expect(result.states[0].deny.has(target)).toBe(false)
  })

  test('a wildcard `res` authorises revoking any device — the management capability shape', async () => {
    // The capability a management device actually holds: one grant covering every device, minted
    // before any of them existed. An adapter that only ever matched `res` exactly would pass every
    // other test in this file and fail here.
    const cap = await mintCapability({ res: '*' })

    const first = await foldWithCapability(cap, { deny: target })
    expect(first.ok).toBe(true)
    if (first.ok) expect(first.states[1].deny.has(target)).toBe(true)

    const second = await foldWithCapability(cap, { deny: bystander })
    expect(second.ok).toBe(true)
    if (second.ok) expect(second.states[1].deny.has(bystander)).toBe(true)
  })

  test('a key target goes through the same `res` check as a DID target', async () => {
    // A `rev` target may name a key — `#<the multibase key exactly as it appears in `k`>` — and the
    // permission model must not have a hole at the new spelling: the target is still what `res`
    // has to cover. A wildcard management grant covers it, an exactly-matching grant covers it, and
    // a grant naming some other resource does not.
    //
    // The controller here is a single-event log, so the key it publishes is current and cannot be
    // denied. This exercises the authorisation half; the fold's refusal to deny a current key is
    // `controller/test/fold.test.ts`.
    const retired = '#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

    const wildcard = await foldWithCapability(await mintCapability({ res: '*' }), { deny: retired })
    expect(wildcard.ok).toBe(true)
    if (wildcard.ok) expect(wildcard.states[1].deny.has(retired)).toBe(true)

    const exact = await foldWithCapability(await mintCapability({ res: retired }), {
      deny: retired,
    })
    expect(exact.ok).toBe(true)

    // Control: the same key target, a grant that names a different resource. Without it, an
    // implementation that skipped the `res` check whenever the target started with `#` would pass
    // both rows above.
    const mismatched = await foldWithCapability(await mintCapability({ res: bystander }), {
      deny: retired,
    })
    expect(mismatched.ok).toBe(false)
  })

  test('a capability whose `res` names a different DID does not authorise the revoke', async () => {
    const result = await foldWithCapability(await mintCapability({ res: bystander }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })

  test('a capability whose `res` names the controller does not authorise revoking a device', async () => {
    // `res` is the *target* of the revoke, never its subject. Passing the controller DID as the
    // resource would make this grant — which names no device at all — revoke any device.
    const result = await foldWithCapability(await mintCapability({ res: controller.did }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })

  test('a capability minted for a different controller does not authorise this revoke', async () => {
    // Everything else is impeccable: signed by its issuer, unexpired, `act: revoke`, `res` naming
    // exactly this target, audience the delegate that signed the event. The only thing wrong is
    // that it speaks for another profile. Without the `sub === subject` binding, one profile's
    // management capability revokes devices on every other profile.
    const cap = await mintCapability({ issuer: otherController })
    const result = await foldWithCapability(cap)

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })

    // Control: the identical capability, differing only in which controller minted it, folds.
    const sameShape = await mintCapability({ issuer: controller })
    await expect(foldWithCapability(sameShape)).resolves.toMatchObject({ ok: true })
  })

  test('an expired capability does not authorise the revoke', async () => {
    const result = await foldWithCapability(await mintCapability({ exp: now() - 60 }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })

  test('a capability whose audience is not the revoke signer does not authorise it', async () => {
    // The capability is valid and grants exactly this revoke — to the outsider. The delegate
    // signs the event anyway. The log is public, so the serialized capability inside it is
    // readable by anyone; without binding the audience to the event's signature, every reader of
    // the log could lift a management capability out of it and revoke whatever its `res` covers.
    const cap = await mintCapability({
      aud: outsider.id,
      cnf: confirmationForSeed(outsiderSeed),
    })
    const result = await foldWithCapability(cap, { signerSeed: delegateSeed })

    expect(result).toEqual({
      ok: false,
      reason: 'revoke is not signed by the capability audience',
      index: 1,
    })

    // Control: the same capability, with the event signed by the audience it names, folds.
    await expect(foldWithCapability(cap, { signerSeed: outsiderSeed })).resolves.toMatchObject({
      ok: true,
    })
  })

  test('the verifyToken hook runs on the capability the event names', async () => {
    // Where a revocation check goes. `checkCapability` only runs the hook on the parents of the
    // capability it is given, so an undelegated management capability — the common shape — would
    // never be checked at all if this call site did not run it.
    const cap = await mintCapability()
    const seen: Array<string> = []
    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap },
    )
    const events = [controller.inception, revoke]

    const observed = await foldLogAsync(controller.did, events, {
      verifyCapability: createControllerCapabilityVerifier({
        methods,
        verifyToken: (_token, raw) => {
          seen.push(raw)
        },
      }),
    })
    expect(observed.ok).toBe(true)
    expect(seen).toEqual([cap])

    // A hook that throws — a revoked capability — denies the revoke rather than being swallowed
    // somewhere that leaves the log folding.
    const rejected = await foldLogAsync(controller.did, events, {
      verifyCapability: createControllerCapabilityVerifier({
        methods,
        verifyToken: () => {
          throw new Error('revoked')
        },
      }),
    })
    expect(rejected).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })

  test('a capability granting a different action does not authorise a revoke', async () => {
    // The `act` half of the convention. A narrow grant over the very same device — read it, do not
    // revoke it — must not deny it. An adapter that asked for whatever action the capability
    // happened to grant, rather than for `revoke`, would accept this.
    const result = await foldWithCapability(await mintCapability({ act: 'read' }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })

    // Control: the identical capability differing only in `act` folds, so the rejection is the
    // action and not the resource, the audience or the pin.
    await expect(
      foldWithCapability(await mintCapability({ act: 'revoke' })),
    ).resolves.toMatchObject({ ok: true })
  })

  test('a capability pinning no audience key is rejected, and says so', async () => {
    // Mandatory on this path, and never filled in by resolving the audience — that fallback is the
    // bug the pin exists to remove. Its own reason, because a sound grant with a missing pin is a
    // minting fault, not a rejected delegation.
    const result = await foldWithCapability(await mintCapability({ cnf: undefined }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability pins no audience key',
      index: 1,
    })
  })

  test('a capability whose pinned key is unreadable is rejected as a missing pin', async () => {
    const result = await foldWithCapability(
      await mintCapability({ cnf: { kid: 'not-a-multibase-key' } }),
    )

    expect(result).toEqual({
      ok: false,
      reason: 'capability pins no audience key',
      index: 1,
    })
  })

  test('a pin naming a key the audience does not carry is rejected, and says so', async () => {
    // Authority follows the pin and revocation follows `aud`, so a capability where they are
    // different parties is a revoke authority the deny set cannot reach: deny the `aud` and the
    // pinned key carries on, deny the key's own DID and the capability never named it. Only the pin
    // moves here — `aud` still names the delegate, whose `did:key` carries its key for comparison.
    const result = await foldWithCapability(
      await mintCapability({ cnf: confirmationForSeed(outsiderSeed) }),
      { signerSeed: outsiderSeed },
    )

    expect(result).toEqual({
      ok: false,
      reason: 'capability pins a key the audience does not carry',
      index: 1,
    })
  })

  test('a pin the audience does carry, signed by somebody else, still fails as an unsigned revoke', async () => {
    // The control that keeps the two failure modes apart: the binding above passes — `aud` and
    // `cnf` are the same delegate — and what fails is the event signature. Both reasons stay
    // reachable, so a caller can tell "the capability is malformed" from "somebody else signed".
    const result = await foldWithCapability(await mintCapability(), {
      signerSeed: outsiderSeed,
    })

    expect(result).toEqual({
      ok: false,
      reason: 'revoke is not signed by the capability audience',
      index: 1,
    })
  })

  test('an audience whose identifier carries no key is refused', async () => {
    // A `did:kokuin:` audience: its key is knowable only by resolving it, and resolving the audience
    // is what the pin exists to remove — so the pin cannot be tied to the party the deny set names,
    // and the capability is a revoke authority that revoking cannot reach. This was once accepted
    // with the binding left open, to keep one profile holding a management capability over another
    // workable; that shape is given up, because unbound authority is what it is made of.
    const cap = await mintCapability({
      aud: otherController.did,
      cnf: confirmationForSeed(otherControllerSeed),
    })
    await expect(foldWithCapability(cap, { signerSeed: otherControllerSeed })).resolves.toEqual({
      ok: false,
      reason: REVOKE_AUDIENCE_KEY_MISMATCH,
      index: 1,
    })

    // CONTROL — the identical capability for an audience that does carry its key folds, so what
    // failed above is the binding and not the grant, the pin, or the signature.
    await expect(foldWithCapability(await mintCapability())).resolves.toMatchObject({ ok: true })
  })

  test('minting one is refused where the mistake is cheap', () => {
    // The same rule at the other end. At verification the cost is an unfoldable log and a DID that
    // stops resolving; here it is an error with the capability still in the minter's hands.
    expect(() =>
      assertRevokeCapabilityAudience({
        aud: otherController.did,
        cnf: confirmationForSeed(otherControllerSeed),
      }),
    ).toThrow(REVOKE_AUDIENCE_KEY_MISMATCH)
    expect(() => assertRevokeCapabilityAudience({ aud: delegate.id })).toThrow(
      REVOKE_NO_AUDIENCE_KEY,
    )
    // CONTROL — the audience that carries its own key passes.
    expect(() =>
      assertRevokeCapabilityAudience({ aud: delegate.id, cnf: confirmationForSeed(delegateSeed) }),
    ).not.toThrow()
  })

  test('a did:peer:4 long-form audience is bound to the keys its document publishes', async () => {
    // The other identifier that carries its key. The long form embeds the document, so the
    // `authentication` key is readable from the string alone — no resolution, same as `did:key`.
    const peer = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    expect(peer.longForm).not.toBe(peer.id)

    // Control: the document's own key binds, and the holder authors the revoke.
    const bound = await mintCapability({
      aud: peer.longForm,
      cnf: audienceConfirmation({ alg: 'EdDSA', publicKey: peer.publicKey }),
    })
    const revoke = createRevokeWithKey(
      peer.privateKey,
      controller.did,
      controller.inception.event,
      target,
      { cap: bound },
    )
    await expect(
      foldLogAsync(controller.did, [controller.inception, revoke], {
        verifyCapability: createControllerCapabilityVerifier({ methods }),
      }),
    ).resolves.toMatchObject({ ok: true })

    // Only the pin moves: another key, the same long-form audience.
    const unbound = await mintCapability({
      aud: peer.longForm,
      cnf: confirmationForSeed(outsiderSeed),
    })
    await expect(foldWithCapability(unbound, { signerSeed: outsiderSeed })).resolves.toEqual({
      ok: false,
      reason: 'capability pins a key the audience does not carry',
      index: 1,
    })
  })

  test('a delegated capability authorises the revoke, and the hook sees every link', async () => {
    // Two levels — controller → manager → delegate — so `checkCapability`'s delegation branch runs
    // rather than its self-issued one, and the pin on the leaf is what the fold checks.
    const manager = identityForSeed(new Uint8Array(32).fill(17))
    const root = await mintCapability({
      aud: manager.id,
      res: '*',
      cnf: confirmationForSeed(new Uint8Array(32).fill(17)),
    })
    const leaf = await mintCapability({
      signer: manager,
      sub: controller.did,
      aud: delegate.id,
      res: target,
      parentCapability: root,
      cap: [root],
    })

    const seen: Array<string> = []
    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap: leaf },
    )
    const result = await foldLogAsync(controller.did, [controller.inception, revoke], {
      verifyCapability: createControllerCapabilityVerifier({
        methods,
        verifyToken: (_token, raw) => {
          seen.push(raw)
        },
      }),
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(target)).toBe(true)
    // The adapter supplies the leaf, `checkCapability` supplies the root — no link unchecked, and
    // no double invocation on the leaf.
    expect(seen).toEqual([leaf, root])
  })

  test('the audience is never resolved, and now cannot be', async () => {
    // The pin's whole purpose, restated for the audiences that remain. This used to be shown with
    // another profile as the audience, rotating its own key: resolving the audience would have made
    // that routine third-party action stop the revoke verifying, and a revoke that stops verifying
    // makes the log unfoldable and this controller's DID permanently unresolvable.
    //
    // The binding now refuses an audience whose identifier carries no key, so the only audiences
    // that reach here are `did:key` and a `did:peer:4` long form — identifiers whose key material
    // cannot change. The hazard is gone rather than merely avoided, and the mechanism that removed
    // it is still the one under test: no registry is configured at all below, and the revoke folds.
    const cap = await mintCapability()
    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap },
    )
    const result = await foldLogAsync(controller.did, [controller.inception, revoke], {
      // No `methods`: the controller is answered by the resolver the fold supplies, and the audience
      // is answered by its own identifier. Nothing here can reach the network or a registry.
      verifyCapability: createControllerCapabilityVerifier(),
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(target)).toBe(true)
  })

  test('a capability that never expires cannot authorise a revoke', async () => {
    // An omitted `exp` is not a long grant, it is a permanent one: authority over this log for the
    // life of the profile, with the deny set as the only remedy. A bounded one lapses whether or not
    // anybody notices, which is the asymmetry that matters at an offline verifier.
    const cap = await mintCapability({ exp: undefined })
    await expect(foldWithCapability(cap)).resolves.toEqual({
      ok: false,
      reason: REVOKE_UNBOUNDED_LIFETIME,
      index: 1,
    })

    // CONTROL — the same capability with an expiry folds, so what failed is the missing claim and
    // not the grant, the pin or the signature.
    await expect(foldWithCapability(await mintCapability())).resolves.toMatchObject({ ok: true })
  })

  test('a ceiling on the lifetime is available and off by default', async () => {
    // Presence is mandated, length is not: the management capability is minted by the *root*, which
    // is cold, so a short ceiling would mean reaching for the hardware to renew and a rule nobody
    // keeps. A caller with a policy can still set one.
    const longLived = await mintCapability({ exp: now() + 365 * 24 * 3600 })
    await expect(foldWithCapability(longLived)).resolves.toMatchObject({ ok: true })

    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap: longLived },
    )
    const result = await foldLogAsync(controller.did, [controller.inception, revoke], {
      verifyCapability: createControllerCapabilityVerifier({ maxLifetimeSeconds: 24 * 3600 }),
    })
    expect(result).toMatchObject({ ok: false })
  })

  test('a device holding the capability and no seed at all authors the revoke', async () => {
    // The actor this whole feature exists for, and the one every other test in this file quietly
    // avoids. Every delegate above is built from a *seed* and reads `authorityPath(0, 0, 0)` out of
    // it — the shape of a controller root, which is precisely what handing a device a capability is
    // meant to make unnecessary. This device holds one Ed25519 key and nothing else: no profile
    // seed, no derivation path, no knowledge of the controller's key schedule.
    const device = randomIdentity()
    const cap = await mintCapability({
      aud: device.id,
      cnf: audienceConfirmation({ alg: 'EdDSA', publicKey: device.publicKey }),
    })

    const revoke = createRevokeWithKey(
      device.privateKey,
      controller.did,
      controller.inception.event,
      target,
      { cap },
    )
    const result = await foldLogAsync(controller.did, [controller.inception, revoke], {
      verifyCapability: createControllerCapabilityVerifier({ methods }),
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(target)).toBe(true)

    // Control: another seedless device, holding no capability naming it, cannot author the same
    // revoke — so what folded above is the grant, not merely the new builder.
    const outsiderDevice = randomIdentity()
    const stolen = createRevokeWithKey(
      outsiderDevice.privateKey,
      controller.did,
      controller.inception.event,
      target,
      { cap },
    )
    await expect(
      foldLogAsync(controller.did, [controller.inception, stolen], {
        verifyCapability: createControllerCapabilityVerifier({ methods }),
      }),
    ).resolves.toEqual({
      ok: false,
      reason: 'revoke is not signed by the capability audience',
      index: 1,
    })
  })

  test('the pinned key is encoded exactly as a controller log encodes the keys in `k`', async () => {
    // One format, two implementations — the packages cannot share code without a cycle. A drift
    // here would only surface as a signature that mysteriously does not match. This is also what
    // makes `cnf.kid` honest as a key *identifier* rather than a reference needing resolution: the
    // string is the same one the log publishes for that key.
    const { publicKey } = deriveKeyPair(delegateSeed, authorityPath(0, 0, 0), 'EdDSA')
    expect(audienceConfirmation({ alg: 'EdDSA', publicKey })).toEqual({
      kid: encodeKey(publicKey, 'EdDSA'),
    })
  })

  test('a confirmation claim with no member this understands is rejected as a missing pin', async () => {
    // RFC 7800 allows `jwk`, `jwe` and `jku` alongside `kid`. None is understood here: `jwk` would
    // be a second encoding of a key this stack already encodes, and `jwe`/`jku` are references to
    // resolve, which is the thing the pin exists to stop. All fail closed, and as a *missing* pin
    // rather than as a rejected delegation.
    // Every RFC 7800 member below type-checks against `ConfirmationClaim` without a cast, which is
    // the point of leaving it open — carrying a `jwk` alongside is a typing question, not a fight
    // with excess-property checking. Only the non-string `kid` needs one, because the type is
    // right to reject it.
    const claims: Array<ConfirmationClaim> = [
      {},
      { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' } },
      { jku: 'https://example.com/keys' },
      { kid: 42 } as unknown as ConfirmationClaim,
      { kid: confirmationForSeed(delegateSeed).kid?.slice(0, 12) },
      // The delegate's real key, correctly encoded, under the wrong member. Only `kid` is read,
      // so this authorises nothing — an implementation scanning `cnf` for any usable string would
      // accept it and quietly widen the claim to members it does not implement.
      { jwk: confirmationForSeed(delegateSeed).kid },
    ]

    for (const cnf of claims) {
      const result = await foldWithCapability(await mintCapability({ cnf }))
      expect(result).toEqual({
        ok: false,
        reason: 'capability pins no audience key',
        index: 1,
      })
    }

    // Control: the same shape with a readable `kid` folds, so the rejections above are the claim
    // and not the surrounding capability.
    await expect(foldWithCapability(await mintCapability())).resolves.toMatchObject({ ok: true })
  })

  test('with no registry at all, the profile is still resolved — by the fold', async () => {
    // `did:kokuin:` cannot be resolved from the identifier alone, and the capability is issued by
    // the very profile being folded. The fold hands the verifier a resolver for that profile at the
    // position being verified, so the one DID a caller cannot configure correctly is the one it
    // never has to.
    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap: await mintCapability() },
    )
    const result = await foldLogAsync(controller.did, [controller.inception, revoke], {
      verifyCapability: createControllerCapabilityVerifier(),
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(target)).toBe(true)
  })

  test('a chain link the registry cannot resolve still fails closed', async () => {
    // The fold's resolver answers for the subject and for nothing else, so a delegation through a
    // *second* profile is exactly as unresolvable as it always was. This is what the row above
    // would otherwise quietly weaken.
    const root = await mintCapability({
      aud: otherController.did,
      res: '*',
      cnf: confirmationForSeed(otherControllerSeed),
    })
    const leaf = await mintCapability({
      signer: otherController.identity,
      sub: controller.did,
      aud: delegate.id,
      res: target,
      parentCapability: root,
      cap: [root],
    })
    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap: leaf },
    )
    const events = [controller.inception, revoke]

    await expect(
      foldLogAsync(controller.did, events, {
        verifyCapability: createControllerCapabilityVerifier(),
      }),
    ).resolves.toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })

    // Control: the same chain through a registry that can resolve the intermediate profile folds,
    // so the rejection is the missing resolver and not the chain.
    await expect(
      foldLogAsync(controller.did, events, {
        verifyCapability: createControllerCapabilityVerifier({ methods }),
      }),
    ).resolves.toMatchObject({ ok: true })
  })
})
