import { describe, expect, test } from 'vitest'

import { createInception, createRotate, didFromInception, type SignedEvent } from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

type RotateRunParams = { did: string; icp: SignedEvent; length: number; tag: string }

const seed = new Uint8Array(32).fill(1)
const victim = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

async function build() {
  const icp = await createInception({ seed, profile: 0 })
  return { icp, did: didFromInception(icp.event) }
}

/**
 * A run of `length` rotates from the inception, each a settlement denying `${tag}${i}`. Two runs
 * with different tags diverge at their first rotate: both are signed by the pre-committed key, so
 * neither supersedes the other there.
 */
async function rotateRun({ did, icp, length, tag }: RotateRunParams): Promise<Array<SignedEvent>> {
  const branch: Array<SignedEvent> = [icp]
  let prior = icp.event
  for (let i = 0; i < length; i++) {
    const rot = await createRotate({
      seed,
      profile: 0,
      did,
      prior,
      snapshot: { members: [], deny: [`${victim}${tag}${i}`] },
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
  test('ROW 1: a longer run of rotates does not outrank a rotate it contradicts', async () => {
    const { icp, did } = await build()
    const longer = await rotateRun({ did, icp, length: 3, tag: 'a' })
    const shorter = await rotateRun({ did, icp, length: 1, tag: 'b' })

    const result = await resolveBranches({ did, chains: [longer, shorter] })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.failure).toBe('duplicity')
    expect(result.duplicity.seq).toBe(1)
  })

  test('ROW 2 (control: both runs are valid, not incidentally malformed)', async () => {
    const { icp, did } = await build()
    expect(
      (
        await foldLog({
          did,
          input: {
            chain: await rotateRun({ did, icp, length: 5, tag: 'a' }),
            events: [],
          },
        })
      ).ok,
    ).toBe(true)
    expect(
      (
        await foldLog({
          did,
          input: {
            chain: await rotateRun({ did, icp, length: 1, tag: 'b' }),
            events: [],
          },
        })
      ).ok,
    ).toBe(true)
  })

  test('ROW 3: the answer is the same in every presentation order and at every length', async () => {
    const { icp, did } = await build()
    for (const n of [1, 2, 3, 4]) {
      const a = await rotateRun({ did, icp, length: n + 1, tag: 'a' })
      const b = await rotateRun({ did, icp, length: n, tag: 'b' })
      expect(await resolveBranches({ did, chains: [a, b] })).toEqual(
        await resolveBranches({ did, chains: [b, a] }),
      )
      expect((await resolveBranches({ did, chains: [a, b] })).ok).toBe(false)
    }
  })

  test('ROW 4 (control): a longer branch wins when it is the same history carried further', async () => {
    const { icp, did } = await build()
    const longer = await rotateRun({ did, icp, length: 3, tag: 'a' })
    const prefix = longer.slice(0, 2)
    const result = await resolveBranches({ did, chains: [prefix, longer] })
    expect(result.ok && result.winner).toBe(longer)
  })
})
