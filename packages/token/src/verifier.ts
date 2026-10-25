import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'

import type { SignatureAlgorithm } from './schemas.js'
import { memoizeVerifier } from './verified-memo.js'

/** @internal */
export type Verifier = (
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
) => boolean | Promise<boolean>

/** @internal */
export type Verifiers = Partial<Record<SignatureAlgorithm, Verifier>>

/**
 * The built-in verifiers, each wrapped by {@link memoizeVerifier}: a signature already verified
 * over the same bytes in this process is not re-verified. A verifier passed through the
 * `verifiers` option replaces the default for its algorithm and is not memoized.
 *
 * @internal
 */
export const defaultVerifiers: Verifiers = {
  ES256: memoizeVerifier(
    'ES256',
    (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => {
      return p256.verify(signature, message, publicKey, { lowS: true })
    },
  ),
  EdDSA: memoizeVerifier(
    'EdDSA',
    (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => {
      return ed25519.verify(signature, message, publicKey)
    },
  ),
}

/** @internal */
export function getVerifier(algorithm: SignatureAlgorithm, verifiers: Verifiers = {}): Verifier {
  const verifier = verifiers[algorithm] ?? defaultVerifiers[algorithm]
  if (verifier == null) {
    throw new Error('Unsupported signature algorithm')
  }
  return verifier
}
