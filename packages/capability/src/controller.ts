import { CODECS, encodeMultibase, type ResolvedSigningKey } from '@kokuin/token'

import type { ConfirmationClaim } from './types.js'

/**
 * Build the `cnf` claim pinning an audience's signing key -- see {@link ConfirmationClaim}.
 *
 * Encoded exactly as a controller log encodes `k` (multicodec-tagged, then multibase), so a human
 * can compare a log against a capability by eye; the format is shared rather than the code, since
 * importing the controller's encoder would cycle. A test asserts the two agree byte for byte.
 *
 * Call at mint time, with the key the audience holds -- from the identifier for a `did:key`, from
 * `resolveIssuer` for anything else.
 */
export function audienceConfirmation(key: ResolvedSigningKey): ConfirmationClaim {
  const codec = CODECS[key.alg]
  const bytes = new Uint8Array(codec.length + key.publicKey.length)
  bytes.set(codec, 0)
  bytes.set(key.publicKey, codec.length)
  return { kid: encodeMultibase(bytes) }
}
