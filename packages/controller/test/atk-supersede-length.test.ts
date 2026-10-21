import { describe, expect, test } from 'vitest'

import { createInception, createRotate, didFromInception, type SignedEvent } from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

const seed = new Uint8Array(32).fill(1)
const victim = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

/**
 * A run of `length` rotates from the inception, each a settlement denying `${tag}${i}`. Two runs
 * with different tags diverge at their first rotate: both are signed by the pre-committed key, so
 * neither supersedes the other there.
 */
function rotateRun(did: string, icp: SignedEvent, length: number, tag: string): Array<SignedEvent> {
  const branch: Array<SignedEvent> = [icp]
  let prior = icp.event
  for (let i = 0; i < length; i++) {
    const rot = createRotate({
      seed,
      profile: 0,
      did,
      prior,
      options: { snapshot: { members: [], deny: [`${victim}${tag}${i}`] } },
    })
    branch.push(rot)
    prior = rot.event
  }
  return branch
}

// `resolveBranches` compares branches at the point they diverge instead of at their heads, so branch
// LENGTH never decides between two histories that contradict each other. The root chain holds only
// `icp`/`rot`, so two branches that both fold and contradict each other diverge on two rotates, and
// no amount of extension on one side settles that: it is duplicity, for a reset to resolve.
describe('superseding is not decided by branch LENGTH', () => {
  test('ROW 1: a longer run of rotates does not outrank a rotate it contradicts', () => {
    const { icp, did } = build()
    const longer = rotateRun(did, icp, 3, 'a')
    const shorter = rotateRun(did, icp, 1, 'b')

    const result = resolveBranches(did, [longer, shorter])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.failure).toBe('duplicity')
    expect(result.duplicity.seq).toBe(1)
  })

  test('ROW 2 (control: both runs are valid, not incidentally malformed)', () => {
    const { icp, did } = build()
    expect(foldLog(did, { chain: rotateRun(did, icp, 5, 'a'), events: [] }).ok).toBe(true)
    expect(foldLog(did, { chain: rotateRun(did, icp, 1, 'b'), events: [] }).ok).toBe(true)
  })

  test('ROW 3: the answer is the same in every presentation order and at every length', () => {
    const { icp, did } = build()
    for (const n of [1, 2, 3, 4]) {
      const a = rotateRun(did, icp, n + 1, 'a')
      const b = rotateRun(did, icp, n, 'b')
      expect(resolveBranches(did, [a, b])).toEqual(resolveBranches(did, [b, a]))
      expect(resolveBranches(did, [a, b]).ok).toBe(false)
    }
  })

  test('ROW 4 (control): a longer branch wins when it is the same history carried further', () => {
    const { icp, did } = build()
    const longer = rotateRun(did, icp, 3, 'a')
    const prefix = longer.slice(0, 2)
    const result = resolveBranches(did, [prefix, longer])
    expect(result.ok && result.winner).toBe(longer)
  })
})
