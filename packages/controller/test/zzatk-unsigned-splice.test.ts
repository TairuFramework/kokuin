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
  const rot = createRotate(seed, 0, did, icp.event)
  const rev = createRevoke(seed, 0, did, rot.event, deviceX, { gen: 0, seq: 1 })
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
  return r.states[r.states.length - 1].digest
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
    console.log('attack branch folds:', attackFolds.ok)

    const result = resolveBranches(did, [honest, attackBranch])
    console.log('resolveBranches ok:', result.ok)
    if (result.ok) {
      console.log('winner length:', result.winner.length)
      console.log(
        'winner event types:',
        result.winner.map((e) => e.event.t),
      )
      console.log('superseded (honest events discarded):', result.superseded)
      const folded = foldLog(did, result.winner)
      console.log(
        'winner head deny set:',
        folded.ok ? [...folded.states[folded.states.length - 1].deny] : 'DID NOT FOLD',
      )
      const honestFolded = foldLog(did, honest)
      console.log(
        'honest head deny set:',
        honestFolded.ok
          ? [...honestFolded.states[honestFolded.states.length - 1].deny]
          : 'DID NOT FOLD',
      )
      console.log(
        'winner head keys === inception keys:',
        JSON.stringify(folded.ok ? folded.states[folded.states.length - 1].keys : null) ===
          JSON.stringify(icp.event.k),
      )
    }

    // The fabricated position is now a `sequence gap`: a skipped event may only sit at the next
    // sequence position, so the branch does not fold at all and never reaches comparison.
    expect(attackFolds.ok).toBe(false)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(honest)
    expect(result.superseded).toBe(0)
  })

  test('ROW 2 (control: criticality is the lever): the same event with crit:true loses', () => {
    const { icp, did, honest } = build()
    const critBranch = [icp, forged(did, digestOfPrefix(did, [icp]), { crit: true })]
    const folds = foldLog(did, critBranch)
    console.log('crit:true branch folds:', folds.ok, folds.ok ? '' : folds.reason)

    const result = resolveBranches(did, [honest, critBranch])
    console.log('winner is honest branch:', result.ok && result.winner === honest)
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
    console.log('tame branch folds:', folds.ok)

    const result = resolveBranches(did, [honest, tameBranch])
    console.log('winner is honest branch:', result.ok && result.winner === honest)
    expect(folds.ok).toBe(true)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(honest)
  })

  test('ROW 4 (control: chaining IS enforced): a wrong `p` is rejected', () => {
    const { icp, did } = build()
    const bad = foldLog(did, [icp, forged(did, 'zNotTheDigest')])
    console.log('wrong-p branch folds:', bad.ok, bad.ok ? '' : bad.reason)
    expect(bad.ok).toBe(false)
  })

  test('ROW 5 (control: `i` IS enforced): a wrong controller is rejected', () => {
    const { icp, did } = build()
    const bad = foldLog(did, [
      icp,
      forged(did, digestOfPrefix(did, [icp]), { i: 'did:kokuin:zSomeoneElse' }),
    ])
    console.log('wrong-i branch folds:', bad.ok, bad.ok ? '' : bad.reason)
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
    console.log('junk-sigs branch folds:', r.ok)
    expect(r.ok).toBe(true)

    // At the fabricated position the same blob is rejected — the position check, not a signature.
    const atFabricatedPosition = {
      ...forged(did, digestOfPrefix(did, [icp])),
      sigs: ['AAAA', 'not-base64url-at-all', ''],
    } as unknown as SignedEvent
    const spoofed = foldLog(did, [icp, atFabricatedPosition])
    console.log(
      'same blob at (MAX, MAX):',
      spoofed.ok ? 'ACCEPTED' : `rejected — ${spoofed.reason}`,
    )
    expect(spoofed.ok).toBe(false)
  })

  test('ROW 7: the forged event is also splice-able into the middle of the honest log', () => {
    const { icp, did, rot, rev, honest } = build()
    // A skipped event carries `digest: prior.digest` forward, so the *next* honest event still
    // chains. The log grows, every position after the splice shifts, and the fold is still `ok`.
    const spliced = [icp, forged(did, digestOfPrefix(did, [icp]), { g: 0, s: 1 }), rot, rev]
    const a = foldLog(did, honest)
    const b = foldLog(did, spliced)
    console.log('honest folds:', a.ok, 'spliced folds:', b.ok)
    if (a.ok && b.ok) {
      console.log('honest states:', a.states.length, 'spliced states:', b.states.length)
      console.log(
        'heads identical:',
        a.states[a.states.length - 1].digest === b.states[b.states.length - 1].digest,
      )
      console.log('position of the revoke moved from', 2, 'to', 3)
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
    console.log('recovery branch folds:', foldLog(did, recovered).ok)
    const result = resolveBranches(did, [recovered, attackBranch, honest])
    console.log('winner is the forged branch:', result.ok && result.winner === attackBranch)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toBe(recovered)
  })
})
