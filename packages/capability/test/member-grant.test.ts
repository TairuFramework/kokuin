import {
  type ControllerLog,
  createAdd,
  createControllerResolver,
  createInception,
  createRemove,
  createRenew,
  createReset,
  createRevoke,
  didFromInception,
  digestOf,
  type EpochEvent,
  type EpochSigner,
  encodeKey,
  foldLog,
  type KeyState,
  keyTarget,
  type SignedEvent,
} from '@kokuin/controller'
import {
  createInMemoryDIDCache,
  createSigningIdentity,
  createSigningIdentityForDID,
  type DIDDoc,
  type DIDMethodResolver,
  decodePeer4,
  encodePeer4,
  getPeer4ShortForm,
  type MethodRegistry,
  type SigningIdentity,
  stringifyToken,
  verifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  AUDIENCE_REVOKED,
  type CapabilityPayload,
  checkCapability,
  checkDelegationChain,
  createCapability,
  DEFAULT_MEMBER_GRANT_LIFETIME,
  type DelegationChainOptions,
  MEMBER_GRANT_KEY_MISMATCH,
  MEMBER_GRANT_NO_IAT,
  MEMBER_GRANT_NO_RESOLVER,
  MEMBER_GRANT_NOT_MEMBER,
  MEMBER_GRANT_PAST_LEASE,
  MEMBER_GRANT_TOO_LONG,
} from '../src/index.js'

// Everything here is real: a real inception, real root-signed epoch events, the real controller
// resolver folding them, and grants signed by the member's own key. A stub `resolveMember` once
// agreed with a verifier that checked no signature at all, which is what this file exists to stop.

const seed = new Uint8Array(32).fill(71)
const profile = 0
const icp = createInception(seed, profile)
const did = didFromInception(icp.event)
const root: EpochSigner = { root: { seed, profile } }

/** The verification time every test pins, and a lease a month past it. */
const T = 1_800_000_000
const LEASE = T + 30 * 86_400

function headOf(log: ControllerLog): KeyState {
  const result = foldLog(did, log)
  if (!result.ok) {
    throw new Error(`fixture does not fold: ${result.reason}`)
  }
  return result.head
}

const head = headOf({ chain: [icp], events: [] })

type Member = { signer: SigningIdentity; key: string; did: string }

type Did = `did:${string}:${string}`

/** `value` typed as the DID it is, refused if it is not one. */
function asDID(value: string): Did {
  if (!/^did:[^:]+:./.test(value)) {
    throw new Error(`not a DID: ${value}`)
  }
  return value as Did
}

/** A long-form `did:peer:4` carrying exactly `key` as its one signing key. */
function peerDID(key: string): string {
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase: key }],
    authentication: ['#key-0'],
  } as DIDDoc
  return encodePeer4(doc).longForm
}

function memberOf(fill: number, form: 'key' | 'peer' = 'key'): Member {
  const privateKey = new Uint8Array(32).fill(fill)
  const plain = createSigningIdentity(privateKey)
  const key = encodeKey(plain.publicKey, 'EdDSA')
  if (form === 'key') {
    return { signer: plain, key, did: plain.id }
  }
  const long = peerDID(key)
  return { signer: createSigningIdentityForDID(asDID(long), privateKey), key, did: long }
}

const digest = (signed: SignedEvent<EpochEvent>): string => digestOf(signed.event)

function addOf(member: Member, lease = LEASE): SignedEvent<EpochEvent> {
  return createAdd({
    seed,
    profile,
    did,
    head,
    parents: [head.epoch],
    member: { did: member.did, key: member.key, lease },
  })
}

const m = memberOf(51)
const added = addOf(m)
const add = digest(added)
const peer = memberOf(52, 'peer')
const peerAdded = addOf(peer)
const peerAdd = digest(peerAdded)
const base: ControllerLog = { chain: [icp], events: [added, peerAdded] }

const edge = createSigningIdentity(new Uint8Array(32).fill(61))
const third = createSigningIdentity(new Uint8Array(32).fill(62))
const stranger = memberOf(63)

/** A registry over `log`, frozen for one verification as `member.ts` asks callers to do. */
function serving(log: ControllerLog): { options: DelegationChainOptions; loads: () => number } {
  let count = 0
  const resolver = createControllerResolver({
    loadLog: async (asked) => {
      if (asked !== did) {
        return undefined
      }
      count++
      return log
    },
  })
  return { options: { atTime: T, methods: [resolver.frozen()] }, loads: () => count }
}

const options = (log: ControllerLog = base): DelegationChainOptions => serving(log).options

type Claims = Omit<Partial<CapabilityPayload>, 'mbr'> & { mbr?: unknown; [claim: string]: unknown }

/** The valid grant every refusal below is one claim away from. */
function claims(overrides: Claims = {}): Claims {
  return {
    sub: did,
    aud: edge.id,
    act: 'write',
    res: 'doc/*',
    iat: T - 60,
    exp: T + 3600,
    mbr: { add, g: 0 },
    ...overrides,
  }
}

/** Sign `payload` as `signer`, dropping every claim set to `undefined`. */
async function grantOf(signer: SigningIdentity, payload: Claims): Promise<string> {
  const defined = Object.fromEntries(Object.entries(payload).filter(([, v]) => v !== undefined))
  return stringifyToken(await signer.signToken(defined))
}

const grant = (overrides: Claims = {}, signer = m.signer) => grantOf(signer, claims(overrides))

/** The signed payload of `raw`, as a caller that verified it would hand to `checkCapability`. */
async function payloadOf(raw: string): Promise<CapabilityPayload> {
  return (await verifyToken<CapabilityPayload>(raw, { atTime: T })).payload
}

/** The unverified payload of `raw` — what a caller that skipped `verifyToken` would hand over. */
function rawPayloadOf(raw: string): CapabilityPayload {
  const [, body] = raw.split('.')
  return JSON.parse(Buffer.from(body ?? '', 'base64url').toString('utf8')) as CapabilityPayload
}

/** The edge holder's invocation of `chain`, the chain-root path. */
async function invocation(chain: Array<string>, holder = edge): Promise<CapabilityPayload> {
  const signed = await holder.signToken({ sub: did, cap: chain })
  return signed.payload as unknown as CapabilityPayload
}

const permission = { act: 'write', res: 'doc/1' }

/**
 * Mark `check` handled, so a rejection is not reported as unhandled while an earlier check in the
 * same list is still being awaited. `expect` still sees it reject.
 */
function quiet(check: Promise<void>): Promise<void> {
  check.catch(() => undefined)
  return check
}

/** Both entry points: the grant presented directly, and the grant at the root of an invocation. */
async function bothPaths(
  raw: string,
  opts: () => DelegationChainOptions = () => options(),
): Promise<Array<Promise<void>>> {
  const direct = await payloadOf(raw)
  const invoked = await invocation([raw])
  return [
    quiet(checkCapability(permission, direct, opts())),
    quiet(checkCapability(permission, invoked, opts())),
  ]
}

describe('member-issued grants', () => {
  test('a member grant within its lease and 12 hours verifies, directly and as a chain root', async () => {
    for (const [member, mbr] of [
      [m, { add, g: 0 }],
      [peer, { add: peerAdd, g: 0 }],
    ] as const) {
      const raw = await grant({ mbr }, member.signer)
      for (const check of await bothPaths(raw)) {
        await expect(check).resolves.toBeUndefined()
      }
      await expect(checkDelegationChain(await payloadOf(raw), [], options())).resolves.toBe(
        undefined,
      )
    }
    // The full default lifetime is inside the bound.
    const longest = await grant({ iat: T - 60, exp: T - 60 + DEFAULT_MEMBER_GRANT_LIFETIME })
    for (const check of await bothPaths(longest)) {
      await expect(check).resolves.toBeUndefined()
    }
  })

  test('the presented grant must cover the request', async () => {
    const raw = await grant({ res: 'doc/2' })
    await expect(checkCapability(permission, await payloadOf(raw), options())).rejects.toThrow(
      'Invalid capability: permission not granted',
    )
    await expect(checkCapability(permission, await invocation([raw]), options())).rejects.toThrow(
      'Invalid capability: permission mismatch',
    )
  })

  test('a non-subject root without mbr is still refused as before', async () => {
    const raw = await grant({ mbr: undefined })
    await expect(checkCapability(permission, await payloadOf(raw), options())).rejects.toThrow(
      'Invalid payload: no capability',
    )
    await expect(checkCapability(permission, await invocation([raw]), options())).rejects.toThrow(
      'Invalid capability: issuer should be subject',
    )
  })

  test('a malformed mbr claim is refused', async () => {
    for (const mbr of [
      'member',
      { add: 1, g: 0 },
      { add, g: -1 },
      { add, g: 0.5 },
      { add, g: '0' },
      { add },
      null,
    ]) {
      for (const check of await bothPaths(await grant({ mbr }))) {
        await expect(check, JSON.stringify(mbr)).rejects.toThrow()
      }
    }
    for (const mbr of ['member', { add: 1, g: 0 }, { add, g: -1 }, { add, g: 0.5 }, { add }]) {
      await expect(
        checkCapability(permission, await payloadOf(await grant({ mbr })), options()),
      ).rejects.toThrow(`${MEMBER_GRANT_NOT_MEMBER}: malformed mbr claim`)
    }
  })

  test('a member grant past the issuer lease is refused', async () => {
    // Placed where `exp` can reach the lease while `exp - iat` stays within 12 hours.
    const at = (): DelegationChainOptions => ({ ...options(), atTime: LEASE - 3600 })
    const pastLease = await grant({ iat: LEASE - 3600, exp: LEASE + 1 })
    for (const check of await bothPaths(pastLease, at)) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_PAST_LEASE)
    }
    // CONTROL — ending on the lease itself verifies.
    const onLease = await grant({ iat: LEASE - 3600, exp: LEASE })
    for (const check of await bothPaths(onLease, at)) {
      await expect(check).resolves.toBeUndefined()
    }
    // A grant with no `exp` has no end to bound, so it is past every lease.
    for (const check of await bothPaths(await grant({ exp: undefined }))) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_PAST_LEASE)
    }
    // The lease is read from the log: a renewal extends it with no new grant.
    const renewed: ControllerLog = {
      chain: [icp],
      events: [
        added,
        peerAdded,
        createRenew({ signer: root, did, head, parents: [add], add, lease: LEASE + 3600 }),
      ],
    }
    for (const check of await bothPaths(pastLease, () => ({
      ...options(renewed),
      atTime: LEASE - 3600,
    }))) {
      await expect(check).resolves.toBeUndefined()
    }
  })

  test('a member grant longer than 12 hours is refused, and the limit is configurable', async () => {
    const tooLong = await grant({ iat: T - 60, exp: T - 60 + DEFAULT_MEMBER_GRANT_LIFETIME + 1 })
    for (const check of await bothPaths(tooLong)) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_TOO_LONG)
    }
    // A wider limit admits it, a narrower one refuses a grant the default admits.
    const wider = () => ({ ...options(), maxMemberGrantLifetime: 86_400 })
    for (const check of await bothPaths(tooLong, wider)) {
      await expect(check).resolves.toBeUndefined()
    }
    const narrower = () => ({ ...options(), maxMemberGrantLifetime: 1800 })
    for (const check of await bothPaths(await grant(), narrower)) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_TOO_LONG)
    }
    // CONTROL — the same narrower limit admits a grant within it.
    for (const check of await bothPaths(await grant({ exp: T + 1740 }), narrower)) {
      await expect(check).resolves.toBeUndefined()
    }
  })

  test('a member grant with no iat, or iat in the future, is refused', async () => {
    for (const check of await bothPaths(await grant({ iat: undefined }))) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_NO_IAT)
    }
    const future = await grant({ iat: T + 60, exp: T + 3600 })
    // The signed token itself, as a caller presenting it directly holds it: `payloadOf` would
    // already refuse it.
    await expect(checkCapability(permission, rawPayloadOf(future), options())).rejects.toThrow(
      'Invalid token: issued in the future',
    )
    await expect(checkDelegationChain(rawPayloadOf(future), [], options())).rejects.toThrow(
      'Invalid token: issued in the future',
    )
    await expect(
      checkCapability(permission, await invocation([future]), options()),
    ).rejects.toThrow()
  })

  test('a member grant is held to its own time claims', async () => {
    // Raw payloads, since `payloadOf` would refuse them first: the arm must not lean on the caller.
    const cases: Array<[Claims, string]> = [
      [{ iat: T - 7200, exp: T - 60 }, 'Invalid token: expired'],
      [{ nbf: T + 60 }, 'Invalid token: not yet valid'],
    ]
    for (const [overrides, reason] of cases) {
      const raw = rawPayloadOf(await grant(overrides))
      await expect(checkCapability(permission, raw, options()), reason).rejects.toThrow(reason)
      await expect(checkDelegationChain(raw, [], options()), reason).rejects.toThrow(reason)
    }
  })

  test('a grant from a removed member, a denied member, or a previous generation is refused', async () => {
    const removed = createRemove({ signer: root, did, head, parents: [add], add })
    const revoke = (target: string) =>
      createRevoke({ signer: root, did, head, parents: [add], target })
    const cases: Array<[string, ControllerLog]> = [
      ['removed', { chain: [icp], events: [added, removed] }],
      ['denied by DID', { chain: [icp], events: [added, revoke(m.did)] }],
      ['denied by key', { chain: [icp], events: [added, revoke(keyTarget(m.key))] }],
      ['never added', { chain: [icp], events: [peerAdded] }],
      [
        'reset carrying the member',
        {
          chain: [
            icp,
            createReset(seed, profile, 1, {
              members: [{ did: m.did, key: m.key, add, lease: LEASE }],
              deny: [],
            }),
          ],
          events: [],
        },
      ],
    ]
    const raw = await grant()
    for (const [label, log] of cases) {
      for (const check of await bothPaths(raw, () => options(log))) {
        await expect(check, label).rejects.toThrow(MEMBER_GRANT_NOT_MEMBER)
      }
    }
    // The reset kills the generation-0 grant, not the member: a grant naming generation 1 verifies.
    const carried = at(cases, 4)[1]
    for (const check of await bothPaths(await grant({ mbr: { add, g: 1 } }), () =>
      options(carried),
    )) {
      await expect(check).resolves.toBeUndefined()
    }
    // Another member's incarnation, and a generation the head is not at, name nobody.
    for (const mbr of [
      { add: peerAdd, g: 0 },
      { add, g: 1 },
    ]) {
      for (const check of await bothPaths(await grant({ mbr }))) {
        await expect(check, JSON.stringify(mbr)).rejects.toThrow(MEMBER_GRANT_NOT_MEMBER)
      }
    }
  })

  test('a grant is refused when the subject has no member resolver', async () => {
    const raw = await grant()
    const live = serving(base).options.methods?.[0]
    if (live == null) {
      throw new Error('no resolver')
    }
    const { resolveMember: _, ...withoutMembers } = live
    const registries: Array<[string, MethodRegistry | undefined]> = [
      ['no registry', undefined],
      ['no resolver for the method', []],
      ['a resolver with no resolveMember', [withoutMembers as DIDMethodResolver]],
    ]
    for (const [label, methods] of registries) {
      await expect(
        checkCapability(permission, await payloadOf(raw), { atTime: T, methods }),
        label,
      ).rejects.toThrow(MEMBER_GRANT_NO_RESOLVER)
    }
  })

  test('a grant signed by a did:peer:4 that is not the pinned key is refused', async () => {
    const mbr = { add: peerAdd, g: 0 }
    const attacker = memberOf(64)
    // A long form sharing the member's short prefix but embedding the attacker's document, so its
    // one key is the attacker's. Canonical DID equality reads only the prefix, so the log answers
    // for the real member with the real pin.
    const attackerLong = peerDID(attacker.key)
    const forged = `${getPeer4ShortForm(peer.did)}${attackerLong.slice(getPeer4ShortForm(attackerLong).length)}`
    const { options: forgedOptions } = serving(base)
    await expect(
      forgedOptions.methods?.[0]?.resolveMember?.(did, {
        did: forged,
        ...{ add: peerAdd, gen: 0 },
      }),
    ).resolves.toMatchObject({ lease: LEASE })
    const forgery = await grantOf(
      createSigningIdentityForDID(asDID(forged), new Uint8Array(32).fill(64)),
      claims({ mbr }),
    )
    // A caller handing over the payload without checking the document's hash still gets a refusal:
    // the key the forged document carries is not the pin.
    await expect(checkCapability(permission, rawPayloadOf(forgery), options())).rejects.toThrow(
      MEMBER_GRANT_KEY_MISMATCH,
    )
    await expect(checkDelegationChain(rawPayloadOf(forgery), [], options())).rejects.toThrow(
      MEMBER_GRANT_KEY_MISMATCH,
    )
    // As a chain root the signature is checked against the issuer before membership is asked, and
    // the forged document does not hash to the prefix.
    await expect(
      checkCapability(permission, await invocation([forgery]), options()),
    ).rejects.toThrow('did:peer:4 hash mismatch')

    // The member's own short form carries no key: what signed it cannot be compared with the pin,
    // even when a cache supplies the document and the signature verifies.
    const short = getPeer4ShortForm(peer.did)
    const shortGrant = await grantOf(
      createSigningIdentityForDID(asDID(short), new Uint8Array(32).fill(52)),
      claims({ mbr }),
    )
    const cache = createInMemoryDIDCache()
    await cache.set(short, decodePeer4(peer.did).doc)
    const shortInvocation = await invocation([shortGrant])
    for (const check of [
      quiet(checkCapability(permission, rawPayloadOf(shortGrant), { ...options(), cache })),
      quiet(checkCapability(permission, shortInvocation, { ...options(), cache })),
    ]) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_KEY_MISMATCH)
    }
    // CONTROL — the long form, signed by the pinned key, verifies.
    for (const check of await bothPaths(await grant({ mbr }, peer.signer))) {
      await expect(check).resolves.toBeUndefined()
    }

    // A member's `did:key` issuer whose token another key signed never reaches membership.
    const impostor = createSigningIdentityForDID(asDID(m.did), new Uint8Array(32).fill(64))
    await expect(
      checkCapability(permission, await invocation([await grant({}, impostor)]), options()),
    ).rejects.toThrow()
    // Another DID claiming the member's incarnation is not that member.
    for (const check of await bothPaths(await grant({}, stranger.signer))) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_NOT_MEMBER)
    }
  })

  test('the key check does not lean on the resolver comparing DIDs', async () => {
    // A method whose member answer ignores the asked DID — a resolver bug, or a method where a
    // member's DID does not determine its key. The real resolver is wrapped, not replaced: the pin
    // and lease are still the log's.
    const live = serving(base).options.methods?.[0]
    if (live?.resolveMember == null) {
      throw new Error('no member resolver')
    }
    const { resolveMember } = live
    const careless: DIDMethodResolver = {
      ...live,
      resolveMember: (subject, query) => resolveMember(subject, { ...query, did: m.did }),
    }
    const lax = (): DelegationChainOptions => ({ atTime: T, methods: [careless] })
    // One Ed25519 key, well formed, just not the pinned one.
    for (const check of await bothPaths(await grant({}, stranger.signer), lax)) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_KEY_MISMATCH)
    }
    // CONTROL — the member itself verifies through the same resolver.
    for (const check of await bothPaths(await grant(), lax)) {
      await expect(check).resolves.toBeUndefined()
    }
  })

  test('a grant whose audience the controller denied is refused', async () => {
    const denied: ControllerLog = {
      chain: [icp],
      events: [added, createRevoke({ signer: root, did, head, parents: [add], target: edge.id })],
    }
    for (const check of await bothPaths(await grant(), () => options(denied))) {
      await expect(check).rejects.toThrow(AUDIENCE_REVOKED)
    }
  })

  test('an edge holder may delegate a member grant further under the existing chain rules', async () => {
    const parent = await grant()
    const delegate = async (payload: {
      act?: string
      res?: string
      exp?: number
    }): Promise<string> => {
      const child = await createCapability(
        edge,
        { sub: did, aud: third.id, act: 'write', res: 'doc/1', exp: T + 1800, ...payload },
        undefined,
        { parentCapability: parent, methods: options().methods },
      )
      return stringifyToken(child)
    }
    const child = await delegate({})
    const { options: once, loads } = serving(base)
    await expect(
      checkCapability(permission, await invocation([child, parent], third), once),
    ).resolves.toBeUndefined()
    // Membership, lease and every link's denial come from one fold of the log.
    expect(loads()).toBe(1)

    // Wider than the parent, or outliving it, is refused as for any delegation.
    await expect(
      delegate({ res: 'doc/*', act: 'admin' }).then(async (wider) =>
        checkCapability(permission, await invocation([wider, parent], third), options()),
      ),
    ).rejects.toThrow()
    await expect(delegate({ exp: T + 7200 })).rejects.toThrow(
      'Invalid capability: child expiry exceeds parent capability',
    )

    // Denying either holder on the chain refuses it.
    for (const target of [edge.id, third.id]) {
      const log: ControllerLog = {
        chain: [icp],
        events: [added, createRevoke({ signer: root, did, head, parents: [add], target })],
      }
      await expect(
        checkCapability(permission, await invocation([child, parent], third), options(log)),
        target,
      ).rejects.toThrow(AUDIENCE_REVOKED)
    }

    // A member grant confers no management power: the holder copying the issuer's `mbr` onto a root
    // of its own is not a member, since membership comes only from a root add.
    const usurped = await grantOf(edge, claims({ aud: third.id }))
    const usurpedPayload = await payloadOf(usurped)
    const usurpedInvocation = await invocation([usurped], third)
    for (const check of [
      quiet(checkCapability(permission, usurpedPayload, options())),
      quiet(checkCapability(permission, usurpedInvocation, options())),
    ]) {
      await expect(check).rejects.toThrow(MEMBER_GRANT_NOT_MEMBER)
    }
  })

  test('createCapability mints a member root with mbr, exp and iat', async () => {
    const payload = {
      sub: did,
      aud: edge.id,
      act: 'write',
      res: 'doc/*',
      iat: T - 60,
      exp: T + 3600,
    }
    const minted = await createCapability(m.signer, payload, undefined, {
      member: { add, g: 0 },
    })
    expect(minted.payload).toMatchObject({ iss: m.did, mbr: { add, g: 0 }, iat: T - 60 })
    for (const check of await bothPaths(stringifyToken(minted))) {
      await expect(check).resolves.toBeUndefined()
    }
    // A member root is bounded at mint, so it carries both ends.
    for (const missing of ['exp', 'iat'] as const) {
      const { [missing]: _, ...partial } = payload
      await expect(
        createCapability(m.signer, partial, undefined, { member: { add, g: 0 } }),
        missing,
      ).rejects.toThrow(missing)
    }
    // A malformed claim is refused before signing.
    await expect(
      createCapability(m.signer, payload, undefined, { member: { add, g: -1 } }),
    ).rejects.toThrow('mbr')
    // CONTROL — without the option, a non-subject signer still needs a parent.
    await expect(createCapability(m.signer, payload)).rejects.toThrow('parentCapability required')
  })
})

function at<T>(items: ReadonlyArray<T>, i: number): T {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}
