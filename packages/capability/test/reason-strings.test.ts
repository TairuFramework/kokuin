import {
  CAPABILITY_VERIFIER_FAILED,
  CAPABILITY_VERIFIER_MALFORMED_ANSWER,
  REVOKE_NOT_SIGNED_BY_AUDIENCE,
} from '@kokuin/controller'
import { describe, expect, test } from 'vitest'

import {
  REVOKE_AUDIENCE_KEY_MISMATCH,
  REVOKE_NO_AUDIENCE_KEY,
  REVOKE_NO_POSITION,
  REVOKE_NOT_AUTHORISED,
} from '../src/index.js'

// These seven reasons span two packages and are what a caller has to match on to tell "the grant
// was rejected" from "the capability is malformed for this use" — of which there are two kinds, a
// pin that is missing and a pin that names the wrong party — from "your verifier is broken" from
// "your fold is older than your capability package". They are frozen at publication either way;
// naming them is the part that is still cheap.

describe('the capability-revoke failure reasons are exported', () => {
  test('each names the string the fold and the adapter actually produce', () => {
    // Written out rather than compared to themselves: the point is that these exact sentences are
    // the contract, so changing one has to change this file too.
    expect(REVOKE_NOT_AUTHORISED).toBe('capability does not authorise this revoke')
    expect(REVOKE_NO_AUDIENCE_KEY).toBe('capability pins no audience key')
    expect(REVOKE_AUDIENCE_KEY_MISMATCH).toBe('capability pins a key the audience does not carry')
    expect(REVOKE_NOT_SIGNED_BY_AUDIENCE).toBe('revoke is not signed by the capability audience')
    expect(CAPABILITY_VERIFIER_MALFORMED_ANSWER).toBe(
      'capability verifier returned a malformed answer',
    )
    expect(CAPABILITY_VERIFIER_FAILED).toBe('capability verifier failed')
    expect(REVOKE_NO_POSITION).toBe('capability verifier was called without a log position')
  })

  test('they are distinct, so a caller can tell the seven cases apart', () => {
    const reasons = [
      REVOKE_NOT_AUTHORISED,
      REVOKE_NO_AUDIENCE_KEY,
      REVOKE_AUDIENCE_KEY_MISMATCH,
      REVOKE_NOT_SIGNED_BY_AUDIENCE,
      CAPABILITY_VERIFIER_MALFORMED_ANSWER,
      CAPABILITY_VERIFIER_FAILED,
      REVOKE_NO_POSITION,
    ]
    expect(new Set(reasons).size).toBe(reasons.length)
  })
})
