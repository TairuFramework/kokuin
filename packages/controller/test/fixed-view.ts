import type { DIDMethodResolver } from '@kokuin/token'

import type { KeyState } from '../src/fold.js'
import { resolverOver } from '../src/state-resolver.js'

/**
 * `resolverOver` answering for exactly one profile out of states the test hands it: the same answers
 * the live resolver gives, for a head no log this package folds could produce (a denied head key, a
 * forced saturation). Any other DID is `Unknown DID`.
 */
export function fixedViewResolver(
  did: string,
  states: Array<KeyState>,
  head: KeyState,
): DIDMethodResolver {
  return resolverOver(async (asked) => {
    if (asked !== did) {
      throw new Error(`Unknown DID: ${asked}`)
    }
    return { states, head }
  })
}
