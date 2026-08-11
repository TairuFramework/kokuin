import {
  CAPABILITY_VERIFIER_FAILED,
  CAPABILITY_VERIFIER_MALFORMED_ANSWER,
  REVOKE_NOT_SIGNED_BY_AUDIENCE,
} from '@kokuin/controller'
import { describe, expect, test } from 'vitest'

import { REVOKE_NO_AUDIENCE_KEY, REVOKE_NOT_AUTHORISED } from '../src/index.js'

// These five reasons span two packages and are what a caller has to match on to tell "the grant was
// rejected" from "the capability is malformed for this use" from "your verifier is broken". They
// are frozen at publication either way; naming them is the part that is still cheap.

describe('the capability-revoke failure reasons are exported', () => {
  test('each names the string the fold and the adapter actually produce', () => {
    // Written out rather than compared to themselves: the point is that these exact sentences are
    // the contract, so changing one has to change this file too.
    expect(REVOKE_NOT_AUTHORISED).toBe('capability does not authorise this revoke')
    expect(REVOKE_NO_AUDIENCE_KEY).toBe('capability pins no audience key')
    expect(REVOKE_NOT_SIGNED_BY_AUDIENCE).toBe('revoke is not signed by the capability audience')
    expect(CAPABILITY_VERIFIER_MALFORMED_ANSWER).toBe(
      'capability verifier returned a malformed answer',
    )
    expect(CAPABILITY_VERIFIER_FAILED).toBe('capability verifier failed')
  })

  test('they are distinct, so a caller can tell the five cases apart', () => {
    const reasons = [
      REVOKE_NOT_AUTHORISED,
      REVOKE_NO_AUDIENCE_KEY,
      REVOKE_NOT_SIGNED_BY_AUDIENCE,
      CAPABILITY_VERIFIER_MALFORMED_ANSWER,
      CAPABILITY_VERIFIER_FAILED,
    ]
    expect(new Set(reasons).size).toBe(reasons.length)
  })
})
