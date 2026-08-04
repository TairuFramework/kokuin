import type { MultiKeyIdentity } from './identity.js'
import type { DIDString, SignedToken } from './types.js'

export type RotationPayload = {
  type: 'did-rotation'
  iss?: DIDString
  to: DIDString
  toLongForm: DIDString
  issuedAt: number
}

/**
 * Sign a rotation assertion linking an old identity to a new one.
 * The assertion is a regular signed token issued by the old identity: its `iss` is that identity's
 * DID, in long form for a `did:peer:4` signer since the payload names no audience.
 * Verifiers walking a rotation chain can use this to link related identities.
 */
export async function createRotationAssertion(
  oldIdentity: MultiKeyIdentity,
  newIdentity: MultiKeyIdentity,
  issuedAt: number = Math.floor(Date.now() / 1000),
): Promise<SignedToken<RotationPayload>> {
  return oldIdentity.signToken<RotationPayload>({
    type: 'did-rotation',
    to: newIdentity.id,
    toLongForm: newIdentity.longForm,
    issuedAt,
  })
}
