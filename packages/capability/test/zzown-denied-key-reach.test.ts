import {
  authorityPath,
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRotate,
  deriveKeyPair,
  didFromInception,
  foldLogAsync,
  keyTarget,
  type SignedEvent,
} from '@kokuin/controller'
import {
  createSigningIdentity,
  type MethodRegistry,
  type SigningIdentity,
  stringifyToken,
  verifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  audienceConfirmation,
  checkCapability,
  createCapability,
  createControllerCapabilityVerifier,
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
  now,
  REVOKE_NOT_AUTHORISED,
} from '../src/index.js'

// A denied key must not be usable ANYWHERE a signature is checked against a resolved key — not only
// on the path whose escalation motivated the feature. The failure this file exists to prevent has a
// precedent on this branch: a deny set that was computed, exported and read by nothing stayed inert
// for the whole branch, and no reviewer noticed, because there was no incorrect code to look at.
//
// So every row here consumes a real artefact through a real entry point, and every row has a
// control that differs only in which key signed. The last row is not a refusal at all — it is a
// consequence of the rule, asserted so it cannot go unnoticed.

const seed = new Uint8Array(32).fill(53)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const rotate = createRotate(seed, 0, did, inception.event)
/** The key the inception established, which the rotate retired and the revoke below denies. */
const leaked = inception.event.k[0]
/** icp → rot: the leaked key is retired for new issuance, and nothing more. */
const rotated: Array<SignedEvent> = [inception, rotate]
/** icp → rot → rev(#leaked): the leaked key denied outright. */
const revoked: Array<SignedEvent> = [
  inception,
  rotate,
  createRevoke(seed, 0, did, rotate.event, keyTarget(leaked), { gen: 0, seq: 1 }),
]

function registry(log: Array<SignedEvent>): MethodRegistry {
  return [createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) })]
}

/** Signs as the profile with the leaked key — what holding a since-rotated key gives you. */
const thief = createControllerIdentity(seed, 0, [inception])
/** Signs as the profile with the key it currently holds. */
const owner = createControllerIdentity(seed, 0, revoked)

const holder = createSigningIdentity(new Uint8Array(32).fill(61))

async function mint(signer: SigningIdentity, audience: string): Promise<string> {
  return stringifyToken(
    await createCapability(signer, {
      sub: did,
      aud: audience,
      act: 'write',
      res: 'doc/1',
      exp: now() + 3600,
    }),
  )
}

async function outcome(run: () => Promise<unknown>): Promise<string> {
  try {
    await run()
    return 'ACCEPTED'
  } catch (err) {
    return (err as Error).message
  }
}

describe('a key the profile has revoked', () => {
  test('ROW 1 — verifyToken, head-only: refused, and refused as "not current"', async () => {
    const token = await mint(thief, holder.id)
    const before = await outcome(() => verifyToken(token, { methods: registry(rotated) }))
    const after = await outcome(() => verifyToken(token, { methods: registry(revoked) }))
    console.log('ROW 1:', JSON.stringify({ before, after }))
    // The reason is deliberately recorded as *unchanged*. A key the profile publishes cannot be
    // denied and a rotate cannot establish a denied key, so on any log this package folds a denied
    // key is never in the head's `k` — `headSigningKey` turns it away before the deny check is
    // reached. The deny check's head arm is therefore a guard for a `states` array a caller built
    // or a third party folded, not a live path; `controller/test/resolver.test.ts` reaches it
    // through `createStateResolver`. Recorded here so a future reader does not chase the "wrong"
    // message, and so that losing the invariant shows up as this row changing.
    expect(before).toMatch(/not current/)
    expect(after).toMatch(/not current/)
  })

  test('ROW 2 — verifyToken, historic: refused, where the rotate alone accepted', async () => {
    const token = await mint(thief, holder.id)
    const before = await outcome(() =>
      verifyToken(token, { methods: registry(rotated), historic: true }),
    )
    const after = await outcome(() =>
      verifyToken(token, { methods: registry(revoked), historic: true }),
    )
    // Control: the identical call, one event earlier in the log, accepts. Historic resolution is
    // designed to survive a rotate — that is the whole reason an explicit denial had to exist.
    console.log('ROW 2:', JSON.stringify({ before, after }))
    expect(before).toBe('ACCEPTED')
    expect(after).toMatch(/has revoked/)
  })

  test('ROW 3 — checkCapability: the chain link signed by it is refused', async () => {
    const stolen = await mint(thief, holder.id)
    const honest = await mint(owner, holder.id)
    const invoke = (cap: string) =>
      checkCapability(
        { act: 'write', res: 'doc/1' },
        { iss: holder.id, sub: did, cap: [cap] } as never,
        { methods: registry(revoked) },
      )
    const denied = await outcome(() => invoke(stolen))
    // Control on the same log: a capability from the key the profile holds still grants, so the
    // refusal above is the denial and not the third event breaking resolution for everyone.
    const control = await outcome(() => invoke(honest))
    console.log('ROW 3:', JSON.stringify({ denied, control }))
    expect(denied).toMatch(/has revoked/)
    expect(control).toBe('ACCEPTED')
  })

  test('ROW 4 — the fold: a capability-authorised revoke it signed does not fold', async () => {
    // The path the fold answers for itself, through `createStateResolver` over its own prefix. The
    // delegate's revoke rides a management capability; the question is which key minted that
    // capability, and the prefix's head is what answers it.
    const delegateSeed = new Uint8Array(32).fill(71)
    const cnf = audienceConfirmation({
      alg: 'EdDSA',
      publicKey: deriveKeyPair(delegateSeed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
    })
    const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

    const grant = async (signer: SigningIdentity) =>
      stringifyToken(
        await createCapability(signer, {
          sub: did,
          aud: createSigningIdentity(
            deriveKeyPair(delegateSeed, authorityPath(0, 0, 0), 'EdDSA').privateKey,
          ).id,
          act: 'revoke',
          res: '*',
          exp: now() + 3600,
          cnf,
        }),
      )

    const foldWith = async (cap: string) => {
      // The position here selects which key is derived from `delegateSeed` — the delegate's own,
      // the one the `cnf` above pins — not a position in the profile's key schedule.
      const rev = createRevoke(
        delegateSeed,
        0,
        did,
        revoked[2].event,
        target,
        { gen: 0, seq: 0 },
        { cap },
      )
      // The verifier's own registry deliberately answers from the inception only — the fold's
      // prefix resolver is what must decide, and it shadows this one for the subject.
      return await foldLogAsync(did, [...revoked, rev], {
        verifyCapability: createControllerCapabilityVerifier({
          methods: [createControllerResolver({ loadLog: async () => [inception] })],
        }),
      })
    }

    const stolen = await foldWith(await grant(thief))
    const honest = await foldWith(await grant(owner))
    console.log(
      'ROW 4:',
      JSON.stringify({
        stolen: stolen.ok ? 'FOLDED' : stolen.reason,
        honest: honest.ok ? 'FOLDED' : honest.reason,
      }),
    )
    expect(stolen.ok).toBe(false)
    if (stolen.ok) return
    // `createControllerCapabilityVerifier` collapses every verification failure into one reason on
    // purpose — see the catch in `src/controller.ts` — so the reason cannot name the denial, and
    // the control below is the whole of the evidence that the denial is what rejected it.
    expect(stolen.reason).toBe(REVOKE_NOT_AUTHORISED)
    // Control: the identical event, the identical grant shape, minted by the live key — so what
    // the fold rejected is the minting key and not the management tier itself.
    expect(honest.ok).toBe(true)
  })

  test('ROW 5 — a revocation record the denied key signed keeps revoking', async () => {
    // ROUND 3 — this row's assertion is FLIPPED and its construction is byte-for-byte what it was.
    //
    // As written it recorded a consequence the round that built it accepted: `createRevocationChecker`
    // ignores a record whose `kid` names a key the issuer does not hold, a denied key is one of
    // those, and so revoking a leaked key un-revoked whatever that key's records had revoked. The
    // reasoning for accepting it was sound as far as it went — `kid` is unauthenticated and the
    // backend is an untrusted extension point, so honouring every unverifiable record would let
    // anyone deny every capability a profile ever issued by planting one per `jti`.
    //
    // What it missed is that the two cases are distinguishable. A key the log never published is a
    // forgery and is still ignored (that DoS is unchanged, and `zzown-key-denial-check.test.ts`
    // holds it). A key the log published and has since denied is not: producing the record required
    // that key's private half, and honouring a revocation only ever subtracts authority. Leaving it
    // as it was meant the remedy for a compromise silently resurrected revoked grants, which is
    // fail-open on the one path that must never fail open.
    const capability = await createCapability(owner, {
      sub: did,
      aud: holder.id,
      act: 'write',
      res: 'doc/1',
      exp: now() + 3600,
      jti: 'grant-1',
    })
    const raw = stringifyToken(capability)

    const record = await createRevocationRecord(thief, 'grant-1')
    // Stored before the denial, which is the realistic order — `add` verifies on the way in, so a
    // record the profile can no longer resolve could not be added at all afterwards. That is worth
    // stating: the fail-open below is only reachable for records already held.
    const backend = createMemoryRevocationBackend({ methods: registry(rotated) })
    await backend.add(record)

    const check = async (log: Array<SignedEvent>) => {
      const methods = registry(log)
      return await outcome(() =>
        checkCapability(
          { act: 'write', res: 'doc/1' },
          { iss: holder.id, sub: did, cap: [raw] } as never,
          { methods, verifyToken: createRevocationChecker(backend, { methods }) },
        ),
      )
    }

    // Before the denial the record verifies and revokes. After it, the record no longer verifies —
    // and is honoured anyway, because the key it names is one this log published and then denied.
    const before = await check(rotated)
    const after = await check(revoked)
    console.log('ROW 5:', JSON.stringify({ before, after }))
    expect(before).toMatch(/Token revoked/)
    expect(after).toMatch(/Token revoked/)
  })
})
