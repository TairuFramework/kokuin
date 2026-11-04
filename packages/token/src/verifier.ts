import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { maybeYield } from '@sozai/async'

import type { CryptoOptions } from './identity.js'
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

const providers = new WeakMap<CryptoProvider, Verifiers>()

function providerVerifiers(crypto: CryptoProvider): Verifiers {
  let verifiers = providers.get(crypto)
  if (verifiers === undefined) {
    verifiers = {}
    for (const alg of ['EdDSA', 'ES256'] as const) {
      verifiers[alg] = memoizeVerifier(alg, async (signature, message, publicKey) => {
        await maybeYield()
        return crypto.verify(alg, signature, message, publicKey)
      })
    }
    providers.set(crypto, verifiers)
  }
  return verifiers
}

/** @internal */
export const defaultVerifiers: Verifiers = providerVerifiers(nobleCrypto)

/** Custom overrides own their algorithm's policy and bypass the signature memo. */
export function getVerifier(
  algorithm: SignatureAlgorithm,
  verifiers: Verifiers = {},
  options: CryptoOptions = {},
): Verifier {
  const verifier =
    verifiers[algorithm] ?? providerVerifiers(options.crypto ?? nobleCrypto)[algorithm]
  if (verifier == null) throw new Error('Unsupported signature algorithm')
  return verifier
}
