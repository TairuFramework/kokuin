import type { DIDMethodResolver } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  decodeKey,
  didFromInception,
  type SignedEvent,
} from '../src/events.js'
import { type CapabilityAuthorisation, foldLog } from '../src/fold.js'
import { createControllerResolver } from '../src/resolver.js'
import { createStateResolver } from '../src/state-resolver.js'
import { buildTwoKeyLog, strangerKey } from './two-key-log.js'

const seed = new Uint8Array(32).fill(1)
const device = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
// Not the controller's seed: the revoke below is signed by a delegate, so only the capability it
// carries can authorise it.
const delegateSeed = new Uint8Array(32).fill(3)
const cap = 'eyJ.delegated.revoke'
/** What the capability pins as its audience key: the key the delegate signs the revoke with. */
const authorised: CapabilityAuthorisation = {
  authorised: true,
  audienceKey: {
    alg: 'EdDSA',
    publicKey: deriveKeyPair(delegateSeed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
  },
}
const declined = { authorised: false, reason: 'capability does not authorise this revoke' } as const

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

/** A log whose last event is a capability-authorised revoke — foldable only asynchronously. */
function capLog() {
  const { icp, did } = build()
  const rev = createRevoke(delegateSeed, 0, did, icp.event, device, { gen: 0, seq: 0 }, { cap })
  return { icp, did, log: [icp, rev] }
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
    expect(resolved.publicKey).toEqual(decodeKey(icp.event.k[0]).publicKey)
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
    const rot = createRotate(seed, 0, did, icp.event)
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const resolved = await resolver.resolve(did, {})
    expect(resolved.publicKey).toEqual(decodeKey(rot.event.k[0]).publicKey)
    expect(resolved.publicKey).not.toEqual(decodeKey(icp.event.k[0]).publicKey)
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
    const rot = createRotate(seed, 0, did, icp.event)
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const retired = icp.event.k[0]

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
    expect(head.publicKey).toEqual(decodeKey(rot.event.k[0]).publicKey)
  })

  test('a kid naming a key from a superseded generation is rejected', async () => {
    const { icp, did } = build()
    const reset = createReset(seed, 0, 1)
    const resolver = createControllerResolver({ loadLog: async () => [icp, reset] })
    const retired = icp.event.k[0]

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

describe('createControllerResolver() with a capability-authorised revoke', () => {
  test('rejects the log when no verifier is configured', async () => {
    const { did, log } = capLog()
    const resolver = createControllerResolver({ loadLog: async () => log })
    await expect(resolver.resolve(did, {})).rejects.toThrow(/capability/)
  })

  test('resolves it when the configured verifier authorises the capability', async () => {
    const { icp, did, log } = capLog()
    const seen: Array<Array<string>> = []
    const resolver = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async (capability, subject, target) => {
        seen.push([capability, subject, target])
        return authorised
      },
    })

    const resolved = await resolver.resolve(did, {})
    // The revoke establishes no key, so the inception's is still current.
    expect(resolved.publicKey).toEqual(decodeKey(icp.event.k[0]).publicKey)
    // The verifier is handed the capability, the controller it must name as `sub`, and the DID
    // being denied — passing anything else would authorise a revoke of the wrong device.
    expect(seen).toEqual([[cap, did, device]])
  })

  test('rejects it when the configured verifier declines the capability', async () => {
    const { did, log } = capLog()
    const resolver = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async () => declined,
    })
    await expect(resolver.resolve(did, {})).rejects.toThrow(
      /capability does not authorise this revoke/,
    )
  })

  test('applies the verifier to resolveAgreementKey too, not only to resolve', async () => {
    const { icp, did, log } = capLog()
    const declining = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async () => declined,
    })
    await expect(declining.resolveAgreementKey?.(did)).rejects.toThrow(/capability/)

    const accepting = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async () => authorised,
    })
    const keys = await accepting.resolveAgreementKey?.(did)
    // A revoke carries the agreement set forward, so it is still the inception's.
    expect(keys?.[0].publicKey).toEqual(decodeKey(icp.event.ka[0]).publicKey)
  })

  test('the prefix wiring the docs prescribe terminates and resolves', async () => {
    // The correct shape: the outer resolver holds the whole log, and the verifier resolves the
    // capability's issuer through a loader answering with the prefix up to the event carrying it.
    // Nothing re-enters, so nothing stalls. The misconfigured shape is covered below.
    const { did, log } = capLog()
    const prefixed = createControllerResolver({
      loadLog: async () => log,
      verifyCapability: async () => {
        await createControllerResolver({ loadLog: async () => [log[0]] }).resolve(did, {})
        return authorised
      },
    })
    await expect(prefixed.resolve(did, {})).resolves.toBeDefined()
  })

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
    expect(first.publicKey).toEqual(decodeKey(icp.event.k[0]).publicKey)
    expect(second.publicKey).toEqual(first.publicKey)
  })

  test('two concurrent resolutions succeed with a verifier and a cap-bearing log', async () => {
    // The configuration this whole task exists to enable, and the one the round-2 guard broke: a
    // verifier is configured, the log carries a capability-authorised revoke, `loadLog` answers
    // with the prefix as documented, and two resolutions overlap.
    const { icp, did, log } = capLog()
    let entered = 0
    const resolver = createControllerResolver({
      loadLog: async (requested) => {
        entered++
        return requested === did ? log : undefined
      },
      verifyCapability: async () => {
        // The prefix wiring the docs prescribe: a separate loader answering with the log up to the
        // event carrying the capability.
        await createControllerResolver({ loadLog: async () => [icp] }).resolve(did, {})
        return authorised
      },
    })

    const [first, second] = await Promise.all([
      resolver.resolve(did, {}),
      resolver.resolve(did, {}),
    ])
    expect(entered).toBe(1)
    expect(first.publicKey).toEqual(decodeKey(icp.event.k[0]).publicKey)
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
    expect(before.publicKey).toEqual(decodeKey(icp.event.k[0]).publicKey)

    // The log grows between two sequential resolutions.
    const rot = createRotate(seed, 0, did, icp.event)
    log = [icp, rot]
    const after = await resolver.resolve(did, {})

    expect(calls).toBe(2)
    expect(after.publicKey).toEqual(decodeKey(rot.event.k[0]).publicKey)
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
    expect(resolved.publicKey).toEqual(decodeKey(icp.event.k[0]).publicKey)
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

  test('a self-re-entrant loadLog deadlocks quietly rather than spinning', async () => {
    // The misconfiguration: `loadLog` answers with the whole log, so verifying the capability
    // resolves the issuer, which folds the same log, which reaches the same revoke. Nothing can
    // tell that apart from the legitimate concurrency above, so it is not diagnosed — it awaits a
    // fold that cannot settle.
    //
    // What matters is *which kind* of stall it is. One `loadLog` call, no Ed25519 work, and the
    // timer queue still live, so a caller-side timeout catches it. Without the shared fold this is
    // an unbounded await chain that starves the timer queue, and the race below would never
    // settle at all.
    const { did, log } = capLog()
    let entered = 0
    const resolver: DIDMethodResolver = createControllerResolver({
      loadLog: async () => {
        entered++
        return log
      },
      verifyCapability: async () => {
        await resolver.resolve(did, {})
        return authorised
      },
    })

    const outcome = await Promise.race([
      resolver.resolve(did, {}).then(() => 'resolved'),
      new Promise((resolve) => setTimeout(() => resolve('timer fired'), 50)),
    ])
    expect(outcome).toBe('timer fired')
    expect(entered).toBe(1)
  })

  test('the guard is per DID, so two profiles vouching for each other still resolve', async () => {
    // What the guard must not break: the audience is a *different* profile, so resolving it from
    // inside this fold is a legitimate nested resolution, not a cycle.
    const { did, log } = capLog()
    const other = createInception(new Uint8Array(32).fill(21), 0)
    const otherDID = didFromInception(other.event)
    const resolver = createControllerResolver({
      loadLog: async (requested) => (requested === otherDID ? [other] : log),
      verifyCapability: async () => {
        await resolver.resolve(otherDID, {})
        return authorised
      },
    })

    await expect(resolver.resolve(did, {})).resolves.toBeDefined()
  })
})

describe('createControllerResolver().resolveAgreementKey()', () => {
  test('resolves the agreement key set from the folded state', async () => {
    const { icp, did } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    const keys = await resolver.resolveAgreementKey?.(did)
    expect(keys).toHaveLength(1)
    expect(keys?.[0].alg).toBe('X25519')
    expect(keys?.[0].publicKey).toEqual(decodeKey(icp.event.ka[0]).publicKey)
  })

  test('reflects a rotation rather than the inception', async () => {
    const { icp, did } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const keys = await resolver.resolveAgreementKey?.(did)
    expect(keys?.[0].publicKey).toEqual(decodeKey(rot.event.ka[0]).publicKey)
    expect(keys?.[0].publicKey).not.toEqual(decodeKey(icp.event.ka[0]).publicKey)
  })

  test('rejects an unknown DID the same way resolve does', async () => {
    const { did } = build()
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    await expect(resolver.resolveAgreementKey?.(did)).rejects.toThrow(/Unknown DID/)
  })
})

describe('createStateResolver()', () => {
  // What the fold hands a capability-authorised revoke's verifier: a resolver over the states
  // *before* the event being verified. It answers for one profile only, so a verifier can merge it
  // into a wider registry without one profile's key state ever standing in for another's.
  test('answers for its own DID and refuses every other', async () => {
    const { icp, did } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const result = foldLog(did, [icp, rot])
    if (!result.ok) throw new Error('did not fold')
    const resolver = createStateResolver(did, result.states)

    expect(resolver.method).toBe('kokuin')
    await expect(resolver.resolve(did, {})).resolves.toEqual({
      alg: 'EdDSA',
      publicKey: decodeKey(rot.event.k[0]).publicKey,
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

  test('carries the deny set of the position it was built at', async () => {
    const { icp, did } = build()
    const rev = createRevoke(seed, 0, did, icp.event, device, { gen: 0, seq: 0 })
    const result = foldLog(did, [icp, rev])
    if (!result.ok) throw new Error('did not fold')

    // Position 0 — before the revoke — and position 1, from the same fold.
    await expect(
      createStateResolver(did, result.states.slice(0, 1)).resolveDenySet?.(did),
    ).resolves.toEqual(new Set())
    await expect(createStateResolver(did, result.states).resolveDenySet?.(did)).resolves.toEqual(
      new Set([device]),
    )
  })
})
