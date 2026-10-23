import { normalizeDID } from '@kokuin/token'

import { createRotate, type SignedEvent } from './events.js'
import { type FoldResult, foldLog, snapshotOf } from './fold.js'

function foldDeviceChain(did: string, chain: Array<SignedEvent>): FoldResult {
  const folded = foldLog(did, { chain, events: [] })
  if (!folded.ok) return folded
  // Only an inception at index zero advances state. Later non-critical inceptions are skipped.
  const index = chain.findIndex(({ event }, index) => event.t !== (index === 0 ? 'icp' : 'rot'))
  return index === -1
    ? folded
    : { ok: false, reason: 'device revoke requires a root-only chain', index }
}

function deniesSubject(deny: ReadonlySet<string>, subject: string): boolean {
  const canonical = normalizeDID(subject)
  return [...deny].some((entry) => normalizeDID(entry) === canonical)
}

/**
 * Every same-generation rotate newly denying `subject`, in chain order, or an empty array for an
 * invalid chain. A subject revoked, cleared by a reset and revoked again yields both indices.
 */
export function deviceRevokeIndices(
  did: string,
  chain: Array<SignedEvent>,
  subject: string,
): Array<number> {
  const folded = foldDeviceChain(did, chain)
  if (!folded.ok) return []
  const indices: Array<number> = []
  for (let index = 1; index < chain.length; index++) {
    const state = folded.states[index]
    const prior = folded.states[index - 1]
    if (
      chain[index]?.event.t === 'rot' &&
      state != null &&
      prior != null &&
      state.gen === prior.gen &&
      deniesSubject(state.deny, subject) &&
      !deniesSubject(prior.deny, subject)
    ) {
      indices.push(index)
    }
  }
  return indices
}

/** First same-generation rotate newly denying `subject`, or undefined for an invalid chain. */
export function deviceRevokeIndex(
  did: string,
  chain: Array<SignedEvent>,
  subject: string,
): number | undefined {
  return deviceRevokeIndices(did, chain, subject)[0]
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
  if (deniesSubject(head.deny, subject))
    throw new Error('createDeviceRevoke: subject already denied')
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
