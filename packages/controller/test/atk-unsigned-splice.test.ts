import { describe, expect, test } from 'vitest'

import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  type SignedEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

const seed = new Uint8Array(32).fill(1)
const deviceX = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  // The honest history: rotate once, then revoke deviceX.
  const rot = createRotate({ seed, profile: 0, did, prior: icp.event })
  const rev = createRevoke({
    seed,
    profile: 0,
    did,
    prior: rot.event,
    target: deviceX,
    keyPosition: { gen: 0, seq: 1 },
  })
  return { icp, did, rot, rev, honest: [icp, rot, rev] }
}

/**
 * A completely unsigned event of an unknown type. When this attack worked, only `i`, `p` and a
 * falsy `crit` were needed for the fold to skip it: `g` and `s` were never validated for a skipped
 * event, and `sigs` was empty. The default `g`/`s` below are the fabricated ones the attack used;
 * the rows that need a truthful position override them.
 */
function forged(did: string, priorDigest: string, over: Record<string, unknown> = {}): SignedEvent {
  return {
    event: {
      v: 1,
      t: 'nop',
      i: did,
      g: 9_007_199_254_740_991,
      s: 9_007_199_254_740_991,
      p: priorDigest,
      crit: false,
      ...over,
    },
    sigs: [],
  } as unknown as SignedEvent
}

function digestOfPrefix(did: string, events: Array<SignedEvent>): string {
  const r = foldLog(did, events)
  if (!r.ok) throw new Error(`prefix does not fold: ${r.reason}`)
  const head = r.states[r.states.length - 1]
  if (head === undefined) throw new Error('prefix has no states')
  return head.digest
}

// The attack this file records is closed. The constructions below are untouched — the same
// keyless forgery, the same control rows — and only the assertions moved, from "the attack
// succeeds" to "the attack is rejected", so the file keeps working as the regression that would
// notice it reopening. Two guards close it, and the rows below pin each separately: the fold now
// requires a skipped event to sit at the next sequence position, and `resolveBranches` orders
// branches by their folded position rather than by the raw head event.
describe('ATTACK (closed): an unsigned, unknown, non-critical event carries an unchecked (g, s)', () => {
  test('ROW 1 (attack): a truncated log + one unsigned event no longer beats the honest branch', () => {
    const { icp, did, honest } = build()
    // The attacker holds NO key material at all. They take the public inception (or any prefix of
    // the public log), truncate everything after it, and append one forged event.
    const attackBranch = [icp, forged(did, digestOfPrefix(did, [icp]))]

    const attackFolds = foldLog(did, attackBranch)

    const result = resolveBranches(did, [honest, attackBranch])

    // The fabricated position is now a `sequence gap`: a skipped event may only sit at the next
    // sequence position, so the branch does not fold at all and never reaches comparison.
    expect(attackFolds.ok).toBe(false)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(foldLog(did, result.winner).ok).toBe(true)
    expect(result.winner).toBe(honest)
    expect(result.superseded).toBe(0)
  })

  test('ROW 2 (control: criticality is the lever): the same event with crit:true loses', () => {
    const { icp, did, honest } = build()
    const critBranch = [icp, forged(did, digestOfPrefix(did, [icp]), { crit: true })]
    const folds = foldLog(did, critBranch)

    const result = resolveBranches(did, [honest, critBranch])
    expect(folds.ok).toBe(false)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(honest)
  })

  test('ROW 3 (control: the spoofed (g,s) is the lever): honest (g,s) on the same event loses', () => {
    const { icp, did, honest } = build()
    // Byte-for-byte the same forged, unsigned, non-critical event — only `g`/`s` are truthful.
    const tameBranch = [icp, forged(did, digestOfPrefix(did, [icp]), { g: 0, s: 1 })]
    const folds = foldLog(did, tameBranch)

    const result = resolveBranches(did, [honest, tameBranch])
    expect(folds.ok).toBe(true)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(honest)
  })

  test('ROW 4 (control: chaining IS enforced): a wrong `p` is rejected', () => {
    const { icp, did } = build()
    const bad = foldLog(did, [icp, forged(did, 'zNotTheDigest')])
    expect(bad.ok).toBe(false)
  })

  test('ROW 5 (control: `i` IS enforced): a wrong controller is rejected', () => {
    const { icp, did } = build()
    const bad = foldLog(did, [
      icp,
      forged(did, digestOfPrefix(did, [icp]), { i: 'did:kokuin:zSomeoneElse' }),
    ])
    expect(bad.ok).toBe(false)
  })

  test('ROW 6: no signature is checked at all — an arbitrary `sigs` blob is still accepted', () => {
    // Unchanged and deliberately still true: the fold cannot check the signature of a type whose
    // rules it does not know, so a skipped event is accepted with any `sigs` at all. What changed
    // is the reach of that: a skipped event no longer moves state (it never did) and no longer
    // carries a position (it now must sit at the next one), so this buys an attacker a no-op entry
    // in a branch and nothing else.
    const { icp, did } = build()
    const junkSigs = {
      ...forged(did, digestOfPrefix(did, [icp]), { g: 0, s: 1 }),
      sigs: ['AAAA', 'not-base64url-at-all', ''],
    } as unknown as SignedEvent
    const r = foldLog(did, [icp, junkSigs])
    expect(r.ok).toBe(true)

    // At the fabricated position the same blob is rejected — the position check, not a signature.
    const atFabricatedPosition = {
      ...forged(did, digestOfPrefix(did, [icp])),
      sigs: ['AAAA', 'not-base64url-at-all', ''],
    } as unknown as SignedEvent
    const spoofed = foldLog(did, [icp, atFabricatedPosition])
    expect(spoofed.ok).toBe(false)
  })

  test('ROW 7: the forged event is also splice-able into the middle of the honest log', () => {
    const { icp, did, rot, rev, honest } = build()
    // A skipped event carries `digest: prior.digest` forward, so the *next* honest event still
    // chains. The log grows, every position after the splice shifts, and the fold is still `ok`.
    const spliced = [icp, forged(did, digestOfPrefix(did, [icp]), { g: 0, s: 1 }), rot, rev]
    const a = foldLog(did, honest)
    const b = foldLog(did, spliced)
    if (a.ok && b.ok) {
    }
    expect(b.ok).toBe(true)
  })

  test('ROW 8: a forged event no longer outranks a legitimate reset', () => {
    const { icp, did, honest } = build()
    // `g` is `Number.MAX_SAFE_INTEGER`. A reset must carry `g > prior.gen` to be a reset at all,
    // and `resolveBranches` orders by `(gen, seq)` — so no branch the root can ever author outranks
    // this one.
    const attackBranch = [icp, forged(did, digestOfPrefix(did, [icp]))]
    const reset = createReset(seed, 0, 1)
    const recovered = [icp, reset]
    const result = resolveBranches(did, [recovered, attackBranch, honest])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(recovered)
  })
})
