import { runInNewContext } from 'node:vm'
import type { DIDMethodResolver } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import { createInception, createRevoke, didFromInception } from '../src/events.js'
import { type CapabilityAuthorisation, foldLog, foldLogAsync } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const delegateSeed = new Uint8Array(32).fill(9)
const outsiderSeed = new Uint8Array(32).fill(10)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const cap = 'eyJ.fake.token'

/** The key `createRevoke(<seed>, …)` signs with — what a capability pins as its audience key. */
function signingKeyFor(revokeSeed: Uint8Array) {
  return {
    alg: 'EdDSA' as const,
    publicKey: deriveKeyPair(revokeSeed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
  }
}

/** An authorisation naming that key — what a verifier answers when the capability grants. */
function authorisedFor(revokeSeed: Uint8Array): CapabilityAuthorisation {
  return { authorised: true, audienceKey: signingKeyFor(revokeSeed) }
}

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

/** A cap-bearing revoke signed by the delegate, chained onto the inception. */
function capRevoke(did: string, icp: ReturnType<typeof createInception>) {
  return createRevoke({
    seed: delegateSeed,
    profile: 0,
    did,
    prior: icp.event,
    target: stolen,
    keyPosition: { gen: 0, seq: 0 },
    cap,
  })
}

function unknownEvent(did: string, prior: ReturnType<typeof createInception>, crit: boolean) {
  return {
    event: {
      v: 1 as const,
      t: 'xyz' as never,
      i: did,
      g: 0,
      s: 1,
      p: (foldLog(did, [prior]) as { ok: true; states: Array<{ digest: string }> }).states[0]
        .digest,
      crit,
    },
    sigs: [],
  }
}

describe('criticality', () => {
  test('an unknown critical event fails the fold closed', () => {
    const { icp, did } = build()
    const result = foldLog(did, [icp, unknownEvent(did, icp, true)])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/unknown critical event/)
  })

  test('an unknown non-critical event is skipped and the fold continues', () => {
    const { icp, did } = build()
    const result = foldLog(did, [icp, unknownEvent(did, icp, false)])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    // Skipped events do not advance state, so the position maps to the last applied state.
    expect(result.states).toHaveLength(2)
    expect(result.states[1].seq).toBe(0)
  })

  test('an unknown event with no `crit` member fails closed rather than skipping', () => {
    // `crit` is wire data, and an absent member reads as `undefined`. Under a truthiness test that
    // was the skip path, so an unknown type could opt out of criticality by saying nothing at all.
    const { icp, did } = build()
    const { event } = unknownEvent(did, icp, false)
    const { crit: _crit, ...withoutCrit } = event
    const result = foldLog(did, [icp, { event: withoutCrit as typeof event, sigs: [] }])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/no criticality flag/)
  })

  test('a skipped event may only claim the next sequence position', () => {
    // The one event the fold accepts without checking a signature — it cannot, not knowing the
    // type's rules — so its position must not be free wire data. `resolveBranches` orders branches
    // by position, and a fabricated one is a branch nothing the controller authors can outrank.
    const { icp, did } = build()
    const skipped = unknownEvent(did, icp, false)
    for (const [g, s] of [
      [0, Number.MAX_SAFE_INTEGER],
      [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
      [1, 1],
      [0, 0],
      [0, 2],
    ]) {
      const result = foldLog(did, [icp, { ...skipped, event: { ...skipped.event, g, s } }])
      expect(result).toEqual({ ok: false, reason: 'sequence gap', index: 1 })
    }
    // The truthful position still folds.
    expect(foldLog(did, [icp, skipped]).ok).toBe(true)
  })

  test('a revoke is critical, so a verifier that cannot read it never accepts the device', () => {
    const { icp, did } = build()
    const forged = {
      event: { ...unknownEvent(did, icp, true).event, t: 'rev' as never, x: stolen },
      sigs: [],
    }
    expect(foldLog(did, [icp, forged]).ok).toBe(false)
  })
})

describe('capability-authorised revoke', () => {
  test('the sync fold rejects a cap-bearing revoke rather than trusting it', () => {
    const { icp, did } = build()
    const result = foldLog(did, [icp, capRevoke(did, icp)])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/capability/)
  })

  test('the async fold accepts one when the injected verifier approves', async () => {
    const { icp, did } = build()
    const result = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async ({ cap: capability, subject, target }) => {
        expect(subject).toBe(did)
        expect(target).toBe(stolen)
        return capability === cap
          ? authorisedFor(delegateSeed)
          : { authorised: false, reason: 'not this capability' }
      },
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(stolen)).toBe(true)
  })

  test('the async fold rejects one the verifier declines', async () => {
    const { icp, did } = build()
    const result = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async () => ({
        authorised: false,
        reason: 'capability does not authorise this revoke',
      }),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('capability does not authorise this revoke')
  })

  test('the async fold rejects one the authorised party did not sign', async () => {
    // The verifier approves — the capability really does grant this revoke — but to somebody
    // else. The event is the delegate's. Nothing the verifier sees could catch that, which is why
    // it hands back the audience's key instead of a yes.
    const { icp, did } = build()
    const result = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async () => authorisedFor(outsiderSeed),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('revoke is not signed by the capability audience')
  })

  test('a verifier answering with the wrong shape fails closed with a real reason', async () => {
    // The fold is total by contract, and the verifier is caller-supplied code across a package
    // boundary TypeScript cannot police — a stale build still holding the round-0 `null`/key
    // contract is the realistic source. Each of these used to throw a `TypeError` out of
    // `foldLogAsync`, or produce a `FoldResult` whose `reason` was `undefined`.
    const { icp, did } = build()
    const malformed = [
      null,
      undefined,
      { alg: 'EdDSA', publicKey: new Uint8Array(32) },
      { authorised: true },
      { authorised: true, audienceKey: { alg: 'EdDSA' } },
      { authorised: false },
      'nope',
      // A truthy discriminant that is not `true` — the shape untyped code reaches for, and the
      // only one whose key is perfectly well formed, so nothing downstream would catch it.
      { authorised: 'true', audienceKey: signingKeyFor(delegateSeed) },
      { authorised: 1, audienceKey: signingKeyFor(delegateSeed) },
      // A well-formed answer whose reason is not a string would yield `reason: undefined`.
      { authorised: false, reason: 404 },
      // A *present* key that is not key bytes. `publicKey != null` admits every one of these, and
      // each then reaches `ed25519.verify`, where it is a caught throw reported as a signature
      // that does not match — "somebody else signed this revoke" for what is actually a broken
      // verifier. The `ArrayBuffer.isView` check is what keeps those two apart.
      { authorised: true, audienceKey: { alg: 'EdDSA', publicKey: [...new Uint8Array(32)] } },
      { authorised: true, audienceKey: { alg: 'EdDSA', publicKey: 'z6MkNotKeyBytes' } },
      { authorised: true, audienceKey: { alg: 'EdDSA', publicKey: new ArrayBuffer(32) } },
    ]

    for (const answer of malformed) {
      const result = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
        verifyCapability: async () => answer as unknown as CapabilityAuthorisation,
      })
      expect(result).toEqual({
        ok: false,
        reason: 'capability verifier returned a malformed answer',
        index: 1,
      })
    }
  })

  test('a verifier that throws fails closed with a reason rather than escaping the fold', async () => {
    // `foldLogAsync` is documented as total. Our own adapter never throws, but a third party's
    // verifier is caller code — a revocation backend timing out, a resolver rejecting — and a
    // throw is not evidence that the capability authorises anything.
    const { icp, did } = build()

    const thrown = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async () => {
        throw new Error('revocation backend unreachable')
      },
    })
    expect(thrown).toEqual({
      ok: false,
      reason: 'capability verifier failed: revocation backend unreachable',
      index: 1,
    })

    // A non-Error rejection carries no `message`, and must still produce a string reason.
    const rejected = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async () => Promise.reject('nope') as Promise<CapabilityAuthorisation>,
    })
    expect(rejected).toEqual({
      ok: false,
      reason: 'capability verifier failed: nope',
      index: 1,
    })
  })

  test('the verifier is handed the profile at the position being verified', async () => {
    // The fourth argument, and the whole of R-2: what a capability-authorised revoke is checked
    // against is the log *before* it, which nothing outside the fold can name. Asserted here at the
    // fold's own boundary, with a stub verifier, so it holds independently of what
    // `@kokuin/capability` does with the answer.
    const { icp, did } = build()
    const first = createRevoke({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      target: 'did:key:zEarlier',
      keyPosition: { gen: 0, seq: 0 },
    })
    const second = createRevoke({
      seed: delegateSeed,
      profile: 0,
      did,
      prior: first.event,
      target: stolen,
      keyPosition: { gen: 0, seq: 0 },
      cap,
    })

    let retained: DIDMethodResolver | undefined
    const result = await foldLogAsync(did, [icp, first, second], {
      verifyCapability: async ({ subject, subjectAtPosition }) => {
        retained = subjectAtPosition
        expect(subject).toBe(did)
        // The state before event 2: `zEarlier` is denied, `stolen` is not — the revoke naming it
        // is the event being verified.
        await expect(subjectAtPosition.resolveDenySet?.(did)).resolves.toEqual(
          new Set(['did:key:zEarlier']),
        )
        await expect(subjectAtPosition.resolve(did, {})).resolves.toEqual(signingKeyFor(seed))
        return authorisedFor(delegateSeed)
      },
    })
    expect(result.ok).toBe(true)

    // Still the prefix afterwards. A verifier may resolve asynchronously and answer later, and the
    // states array it was built from keeps growing as the fold proceeds — so the resolver has to
    // hold a copy rather than a view of the fold's own array.
    await expect(retained?.resolveDenySet?.(did)).resolves.toEqual(new Set(['did:key:zEarlier']))
    if (!result.ok) return
    expect(result.states[2].deny).toEqual(new Set(['did:key:zEarlier', stolen]))
  })

  test('an audience key from another realm is accepted, not rejected as malformed', async () => {
    // The shape check is the one place this fold can turn away a *correct* answer. `instanceof` is
    // per-realm, so a key that came from a worker, a `vm` context or across an Electron bridge is
    // not `instanceof Uint8Array` here even though it is one. `ArrayBuffer.isView` is realm-safe.
    const { icp, did } = build()
    const own = signingKeyFor(delegateSeed)
    const foreign = runInNewContext('new Uint8Array(bytes)', { bytes: Array.from(own.publicKey) })
    expect(foreign instanceof Uint8Array).toBe(false)

    const result = await foldLogAsync(did, [icp, capRevoke(did, icp)], {
      verifyCapability: async () => ({
        authorised: true,
        audienceKey: { alg: 'EdDSA', publicKey: foreign as Uint8Array },
      }),
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(stolen)).toBe(true)
  })

  test('the async fold rejects a cap-bearing revoke carrying no signature at all', async () => {
    // Before the audience binding, `sigs` was never read on this path: an event with an empty
    // signature list and a lifted capability folded cleanly.
    const { icp, did } = build()
    const unsigned = { ...capRevoke(did, icp), sigs: [] }
    const result = await foldLogAsync(did, [icp, unsigned], {
      verifyCapability: async () => authorisedFor(delegateSeed),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('revoke is not signed by the capability audience')
  })
})
