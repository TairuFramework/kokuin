import { createRotate, type SignedEvent } from './events.js'
import { type FoldResult, foldLog, snapshotOf } from './fold.js'

function foldDeviceChain(did: string, chain: Array<SignedEvent>): FoldResult {
  const folded = foldLog(did, { chain, events: [] })
  if (!folded.ok) return folded
  // The general fold skips non-critical unknown events, including legacy chain revokes.
  const index = chain.findIndex(({ event }) => event.t !== 'icp' && event.t !== 'rot')
  return index === -1
    ? folded
    : { ok: false, reason: 'device revoke requires a root-only chain', index }
}

/** First same-generation rotate newly denying `subject`, or undefined for an invalid chain. */
export function deviceRevokeIndex(
  did: string,
  chain: Array<SignedEvent>,
  subject: string,
): number | undefined {
  const folded = foldDeviceChain(did, chain)
  if (!folded.ok) return undefined
  for (let index = 1; index < chain.length; index++) {
    const state = folded.states[index]
    const prior = folded.states[index - 1]
    if (
      chain[index]?.event.t === 'rot' &&
      state != null &&
      prior != null &&
      state.gen === prior.gen &&
      state.deny.has(subject) &&
      !prior.deny.has(subject)
    ) {
      return index
    }
  }
  return undefined
}

export type CreateDeviceRevokeParams = {
  seed: Uint8Array
  profile: number
  did: string
  chain: Array<SignedEvent>
  subject: string
}

/** Carry the folded snapshot forward in a rotate, adding one previously undenied subject. */
export function createDeviceRevoke({
  seed,
  profile,
  did,
  chain,
  subject,
}: CreateDeviceRevokeParams): SignedEvent {
  const folded = foldDeviceChain(did, chain)
  if (!folded.ok) throw new Error(folded.reason)
  const head = folded.head
  if (head.deny.has(subject)) throw new Error('createDeviceRevoke: subject already denied')
  const prior = chain.at(-1)
  if (prior == null) throw new Error('Missing controller head')
  return createRotate({
    seed,
    profile,
    did,
    prior: prior.event,
    snapshot: { ...snapshotOf(head), deny: [...head.deny, subject] },
  })
}
