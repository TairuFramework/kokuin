import type { DIDMethodResolver } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { decodeKey } from '../src/keys.js'
import { createControllerResolver } from '../src/resolver.js'
import { createStateResolver } from '../src/state-resolver.js'
import { buildTwoKeyLog, strangerKey } from './two-key-log.js'

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const seed = new Uint8Array(32).fill(1)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

describe('createControllerResolver()', () => {
  test('registers for the kokuin method', () => {
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    expect(resolver.method).toBe('kokuin')
  })

  test('resolves the current signing key from the folded log', async () => {
    const { icp, did } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    const resolved = await resolver.resolve(did, {})
    expect(resolved.alg).toBe('EdDSA')
    expect(resolved.publicKey).toEqual(decodeKey(at(icp.event.k, 0)).publicKey)
  })

  test('rejects a DID with no log rather than returning a guess', async () => {
    const { did } = build()
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    await expect(resolver.resolve(did, {})).rejects.toThrow(/Unknown DID/)
  })

  test('rejects a log that does not fold to the requested DID', async () => {
    const { icp } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    await expect(resolver.resolve('did:kokuin:zWRONG', {})).rejects.toThrow()
  })

  test('resolves the rotated key after a rotation, not the original', async () => {
    const { icp, did } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const resolved = await resolver.resolve(did, {})
    expect(resolved.publicKey).toEqual(decodeKey(at(rot.event.k, 0)).publicKey)
    expect(resolved.publicKey).not.toEqual(decodeKey(at(icp.event.k, 0)).publicKey)
  })
})

describe('createControllerResolver().resolve() with a kid', () => {
  test('resolves the key named by kid, not the first key', async () => {
    const { did, log, cosignerKey, controllerKey } = buildTwoKeyLog(seed)
    const resolver = createControllerResolver({ loadLog: async () => log })

    const resolved = await resolver.resolve(did, { kid: `#${controllerKey}` })
    expect(resolved.alg).toBe('EdDSA')
    expect(resolved.publicKey).toEqual(decodeKey(controllerKey).publicKey)
    // Without this second assertion an implementation that ignores `kid` entirely would pass:
    // `keys[0]` is the co-signer's key, so the two must be observably different.
    expect(resolved.publicKey).not.toEqual(decodeKey(cosignerKey).publicKey)
  })

  test('resolves keys[0] when the header carries no kid', async () => {
    const { did, log, cosignerKey } = buildTwoKeyLog(seed)
    const resolver = createControllerResolver({ loadLog: async () => log })

    const resolved = await resolver.resolve(did, {})
    expect(resolved.publicKey).toEqual(decodeKey(cosignerKey).publicKey)
  })

  test('a kid naming a key this profile never published is rejected', async () => {
    const { did, log } = buildTwoKeyLog(seed)
    const resolver = createControllerResolver({ loadLog: async () => log })
    const stranger = strangerKey()

    // Rejected, never answered with `keys[0]`: a verifier told which key signed must not fall
    // back to a different one, which would accept a signature the token never claimed. Both
    // members refuse it — the key is in no key set this profile ever published.
    await expect(resolver.resolve(did, { kid: `#${stranger}` })).rejects.toThrow(
      `Controller ${did} kid names a key that is not current: #${stranger}`,
    )
    await expect(resolver.resolveHistoric?.(did, { kid: `#${stranger}` })).rejects.toThrow(
      `Controller ${did} kid names a key outside the current generation: #${stranger}`,
    )
  })

  test('a kid naming a key the log rotated away is historic-only', async () => {
    const { icp, did } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const retired = at(icp.event.k, 0)

    // A rotate is routine hygiene, so it must not invalidate what the profile signed before it —
    // see `generation-lifecycle.test.ts` for the token-level consequence. That is the historic
    // question, and it has to be asked explicitly.
    const resolved = await resolver.resolveHistoric?.(did, { kid: `#${retired}` })
    expect(resolved?.publicKey).toEqual(decodeKey(retired).publicKey)
    // `resolve` answers the other question — can the profile sign with it now — and the answer is
    // no, which is what makes a rotate retire a leaked key for new issuance.
    await expect(resolver.resolve(did, { kid: `#${retired}` })).rejects.toThrow(
      /kid names a key that is not current/,
    )
    // The head answer is still the rotated key, so the historic resolution really did reach back.
    const head = await resolver.resolve(did, {})
    expect(head.publicKey).toEqual(decodeKey(at(rot.event.k, 0)).publicKey)
  })

  test('a kid naming a key from a superseded generation is rejected', async () => {
    const { icp, did } = build()
    const reset = createReset(seed, 0, 1)
    const resolver = createControllerResolver({ loadLog: async () => [icp, reset] })
    const retired = at(icp.event.k, 0)

    await expect(resolver.resolveHistoric?.(did, { kid: `#${retired}` })).rejects.toThrow(
      /kid names a key outside the current generation/,
    )
    // Control: the same kid resolves against a resolver whose log stops before the reset, so the
    // rejection is the generation bump and not the kid form being unusable.
    const preReset = createControllerResolver({ loadLog: async () => [icp] })
    const resolved = await preReset.resolveHistoric?.(did, { kid: `#${retired}` })
    expect(resolved?.publicKey).toEqual(decodeKey(retired).publicKey)
  })

  test('a kid that is not a fragment is rejected rather than matched bare', async () => {
    const { did, log, controllerKey } = buildTwoKeyLog(seed)
    const resolver = createControllerResolver({ loadLog: async () => log })

    // The format is `#<the multibase key exactly as it appears in `k`>`. Accepting the bare key
    // as well would make two spellings valid forever on a wire-visible format.
    await expect(resolver.resolve(did, { kid: controllerKey })).rejects.toThrow(
      `Controller ${did} kid is not a key fragment: ${controllerKey}`,
    )
  })
})

describe('createControllerResolver() and a revoked key', () => {
  /** icp → rot → rot denying `#<the inception key>`: the leaked key retired, then denied. */
  function revokedKeyLog() {
    const { icp, did } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const leaked = at(icp.event.k, 0)
    const rev = createRotate({
      seed,
      profile: 0,
      did,
      prior: rot.event,
      options: { snapshot: { members: [], deny: [`#${leaked}`] } },
    })
    return { did, leaked, rot, rev, rotated: [icp, rot], revoked: [icp, rot, rev] }
  }

  test('resolveHistoric refuses it — which the rotate alone does not', async () => {
    const { did, leaked, rotated, revoked } = revokedKeyLog()

    // Control, and the whole reason the feature exists: after the rotate the key is retired for
    // new issuance but still answers the historic question, because an already-issued capability
    // has to survive a routine rotate. Rotation is not what retires a key for what it has already
    // signed.
    const afterRotate = createControllerResolver({ loadLog: async () => rotated })
    await expect(afterRotate.resolveHistoric?.(did, { kid: `#${leaked}` })).resolves.toEqual({
      alg: 'EdDSA',
      publicKey: decodeKey(leaked).publicKey,
    })

    // One more event — a rotate whose snapshot denies the key — and the same question is refused.
    const afterRevoke = createControllerResolver({ loadLog: async () => revoked })
    await expect(afterRevoke.resolveHistoric?.(did, { kid: `#${leaked}` })).rejects.toThrow(
      `Controller ${did} kid names a key the controller has revoked: #${leaked}`,
    )
  })

  test('the denial is evaluated at the head, not at the position the key was found at', async () => {
    // The key resolves at position 0, where nothing was denied yet. Anchoring the check there —
    // the position an artefact's `kid` reaches back to — would let a thief be answered from before
    // the revoke, which is the whole class of attack the `aud` rule already closes.
    const { did, leaked, revoked } = revokedKeyLog()
    const resolver = createControllerResolver({ loadLog: async () => revoked })
    const folded = foldLog(did, { chain: revoked, events: [] })
    if (!folded.ok) throw new Error('did not fold')
    expect(at(folded.states, 0).keys).toContain(leaked)
    expect(at(folded.states, 0).deny.size).toBe(0)

    await expect(resolver.resolveHistoric?.(did, { kid: `#${leaked}` })).rejects.toThrow(
      /has revoked/,
    )
  })

  test('the rest of the profile keeps resolving', async () => {
    // The control every row above needs: the revoke must deny one key, not break the log. Without
    // this, a fold that rejected the whole three-event log would look identical from the outside.
    const { did, rot, rev, revoked } = revokedKeyLog()
    const resolver = createControllerResolver({ loadLog: async () => revoked })
    const current = at(rev.event.k, 0)

    await expect(resolver.resolve(did, {})).resolves.toEqual({
      alg: 'EdDSA',
      publicKey: decodeKey(current).publicKey,
    })
    await expect(resolver.resolveHistoric?.(did, { kid: `#${current}` })).resolves.toBeDefined()
    // The key the first rotate established, retired since but never denied, still answers.
    await expect(
      resolver.resolveHistoric?.(did, { kid: `#${at(rot.event.k, 0)}` }),
    ).resolves.toBeDefined()
    await expect(resolver.resolveAgreementKey?.(did)).resolves.toHaveLength(1)
  })

  test('a later snapshot cannot lift it', async () => {
    // A checkpointed retirement outlives every later rotate in the generation: a snapshot leaving
    // it out would hand the thief historic resolution back, so the rotate that tries does not fold
    // and the resolver answers nothing from that log.
    const { did, leaked, rev, revoked } = revokedKeyLog()
    const cleared = createRotate({
      seed,
      profile: 0,
      did,
      prior: rev.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const resolver = createControllerResolver({ loadLog: async () => [...revoked, cleared] })

    await expect(resolver.resolveHistoric?.(did, { kid: `#${leaked}` })).rejects.toThrow(
      /snapshot drops a retired key denial/,
    )
  })
})

describe('createControllerResolver() shared folds', () => {
  test('two concurrent resolutions of one DID share a single fold', async () => {
    // Ordinary parallel verification of two tokens from one issuer. `@kokuin/token` caches only
    // `did:peer:4`, so nothing upstream dedupes `did:kokuin:` and both calls arrive here. They must
    // both succeed — a rejection arrives as `UnresolvableIssuerError`, which the revocation checker
    // rethrows when it names the token's own issuer, denying a perfectly valid capability.
    const { icp, did } = build()
    let release: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    let entered = 0
    const resolver = createControllerResolver({
      loadLog: async () => {
        // Hold the first call open, so if a second one were ever made the two would genuinely
        // overlap rather than happening to serialise. It is never made — that is the assertion.
        entered++
        setTimeout(release, 0)
        await gate
        return [icp]
      },
    })

    const [first, second] = await Promise.all([
      resolver.resolve(did, {}),
      resolver.resolve(did, {}),
    ])
    // One fold, not two: the second resolution joined the first rather than starting its own.
    expect(entered).toBe(1)
    expect(first.publicKey).toEqual(decodeKey(at(icp.event.k, 0)).publicKey)
    expect(second.publicKey).toEqual(first.publicKey)
  })

  test('a later resolution refolds — the shared fold is not a cache', async () => {
    // The one property keeping the in-flight map from serving superseded state forever. If the
    // entry outlived its fold, every later resolution would answer from the first log this
    // resolver ever saw — a rotated-away key still verifying, and a device revoked on the log
    // still passing, for the life of the instance.
    const { icp, did } = build()
    let log: Array<SignedEvent> = [icp]
    let calls = 0
    const resolver = createControllerResolver({
      loadLog: async () => {
        calls++
        return log
      },
    })

    const before = await resolver.resolve(did, {})
    expect(before.publicKey).toEqual(decodeKey(at(icp.event.k, 0)).publicKey)

    // The log grows between two sequential resolutions.
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    log = [icp, rot]
    const after = await resolver.resolve(did, {})

    expect(calls).toBe(2)
    expect(after.publicKey).toEqual(decodeKey(at(rot.event.k, 0)).publicKey)
    expect(after.publicKey).not.toEqual(before.publicKey)
  })

  test('a failed resolution does not stick — the next one retries', async () => {
    // Removal is in `finally`, not on the success path. A `loadLog` that fails transiently — a
    // network blip, a store not yet open — must not wedge the DID on this instance for good.
    const { icp, did } = build()
    let calls = 0
    const resolver = createControllerResolver({
      loadLog: async () => {
        if (++calls === 1) throw new Error('store unavailable')
        return [icp]
      },
    })

    await expect(resolver.resolve(did, {})).rejects.toThrow('store unavailable')
    const resolved = await resolver.resolve(did, {})
    expect(calls).toBe(2)
    expect(resolved.publicKey).toEqual(decodeKey(at(icp.event.k, 0)).publicKey)
  })

  test('a loadLog that re-enters before its first await does not recurse', async () => {
    // The entry is registered a microtask *before* `loadLog` runs, so a `loadLog` that calls back
    // into `resolve` synchronously finds it. Registering after the call would leave the map empty
    // at that moment and recurse until the stack overflows.
    const { icp, did } = build()
    let calls = 0
    const resolver: DIDMethodResolver = createControllerResolver({
      loadLog: async () => {
        calls++
        // Synchronous re-entry: no await before this line.
        void resolver.resolve(did, {}).catch(() => undefined)
        return [icp]
      },
    })

    const outcome = await Promise.race([
      resolver.resolve(did, {}).then(() => 'resolved'),
      new Promise((resolve) => setTimeout(() => resolve('timer fired'), 50)),
    ])
    // Joining the in-flight fold, so the re-entrant call adds no work of its own.
    expect(calls).toBe(1)
    expect(outcome).toBe('resolved')
  })
})

describe('createControllerResolver().resolveAgreementKey()', () => {
  test('resolves the agreement key set from the folded state', async () => {
    const { icp, did } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    const keys = await resolver.resolveAgreementKey?.(did)
    expect(keys).toHaveLength(1)
    const key = keys?.[0]
    if (key === undefined) throw new Error('expected an agreement key')
    expect(key.alg).toBe('X25519')
    expect(key.publicKey).toEqual(decodeKey(at(icp.event.ka, 0)).publicKey)
  })

  test('reflects a rotation rather than the inception', async () => {
    const { icp, did } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const keys = await resolver.resolveAgreementKey?.(did)
    const key = keys?.[0]
    if (key === undefined) throw new Error('expected an agreement key')
    expect(key.publicKey).toEqual(decodeKey(at(rot.event.ka, 0)).publicKey)
    expect(key.publicKey).not.toEqual(decodeKey(at(icp.event.ka, 0)).publicKey)
  })

  test('rejects an unknown DID the same way resolve does', async () => {
    const { did } = build()
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    await expect(resolver.resolveAgreementKey?.(did)).rejects.toThrow(/Unknown DID/)
  })
})

describe('createStateResolver()', () => {
  // A resolver over already-folded states. It answers for one profile only, so it can be merged
  // into a wider registry without one profile's key state ever standing in for another's.
  test('answers for its own DID and refuses every other', async () => {
    const { icp, did } = build()
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const result = foldLog(did, { chain: [icp, rot], events: [] })
    if (!result.ok) throw new Error('did not fold')
    const resolver = createStateResolver(did, result.states)

    expect(resolver.method).toBe('kokuin')
    await expect(resolver.resolve(did, {})).resolves.toEqual({
      alg: 'EdDSA',
      publicKey: decodeKey(at(rot.event.k, 0)).publicKey,
    })
    // A key from an earlier position of the same generation, exactly as the live resolver does:
    // historic only, and refused by `resolve`.
    await expect(
      resolver.resolveHistoric?.(did, { kid: `#${icp.event.k[0]}` }),
    ).resolves.toBeDefined()
    await expect(resolver.resolve(did, { kid: `#${icp.event.k[0]}` })).rejects.toThrow(
      /not current/,
    )
    await expect(resolver.resolveDenySet?.(did)).resolves.toEqual(new Set())
    await expect(resolver.resolveAgreementKey?.(did)).resolves.toHaveLength(1)

    const stranger = 'did:kokuin:zStranger'
    await expect(resolver.resolve(stranger, {})).rejects.toThrow(`Unknown DID: ${stranger}`)
    await expect(resolver.resolveHistoric?.(stranger, {})).rejects.toThrow(/Unknown DID/)
    await expect(resolver.resolveDenySet?.(stranger)).rejects.toThrow(/Unknown DID/)
    await expect(resolver.resolveAgreementKey?.(stranger)).rejects.toThrow(/Unknown DID/)
  })

  // The head arm of the deny check in `signingKeyFrom`. It is unreachable from a log this package
  // folded — the fold refuses to deny a key the profile publishes — but `createStateResolver` is
  // handed a `states` array, and the invariant is the fold's property, not the array's. A third
  // party's fold, or a cached snapshot, can produce one.
  test('refuses a head key the state it was handed also denies', async () => {
    const { icp, did } = build()
    const result = foldLog(did, { chain: [icp], events: [] })
    if (!result.ok) throw new Error('did not fold')
    const head = at(result.states, 0)
    const target = `#${at(head.keys, 0)}`

    // Control: the identical state, identical key, and an empty deny set — so what refuses below
    // is the denial and not the hand-built state.
    await expect(createStateResolver(did, [head]).resolve(did, { kid: target })).resolves.toEqual({
      alg: 'EdDSA',
      publicKey: decodeKey(at(head.keys, 0)).publicKey,
    })

    const denying = createStateResolver(did, [{ ...head, deny: new Set([target]) }])
    await expect(denying.resolve(did, { kid: target })).rejects.toThrow(/has revoked/)
    // And with no `kid` at all, where the answer is volunteered rather than asked for.
    await expect(denying.resolve(did, {})).rejects.toThrow(/has revoked/)
  })

  test('drops an agreement key the state it was handed denies', async () => {
    const { icp, did } = build()
    const result = foldLog(did, { chain: [icp], events: [] })
    if (!result.ok) throw new Error('did not fold')
    const head = at(result.states, 0)

    expect(await createStateResolver(did, [head]).resolveAgreementKey?.(did)).toHaveLength(1)
    const denying = createStateResolver(did, [
      { ...head, deny: new Set([`#${at(head.agreement, 0)}`]) },
    ])
    // Empty rather than an error: to `@kokuin/jwe` that is "nothing to encrypt to", which is the
    // fail-closed direction.
    expect(await denying.resolveAgreementKey?.(did)).toEqual([])
  })

  test('carries the deny set of the position it was built at', async () => {
    const { icp, did } = build()
    const rev = createRotate({
      seed,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [device] } },
    })
    const result = foldLog(did, { chain: [icp, rev], events: [] })
    if (!result.ok) throw new Error('did not fold')

    // Position 0 — before the denying rotate — and position 1, from the same fold.
    await expect(
      createStateResolver(did, result.states.slice(0, 1)).resolveDenySet?.(did),
    ).resolves.toEqual(new Set())
    await expect(createStateResolver(did, result.states).resolveDenySet?.(did)).resolves.toEqual(
      new Set([device]),
    )
  })
})
