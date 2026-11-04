import { type CryptoProvider, nobleCrypto, type VerifyItem } from '@kokuin/crypto'
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

type VerificationBatch = {
  items: Array<VerifyItem>
  yields: Array<Promise<void>>
  result: Promise<Array<boolean>>
}

function providerVerifiers(crypto: CryptoProvider): Verifiers {
  let verifiers = providers.get(crypto)
  if (verifiers === undefined) {
    verifiers = {}
    let pending: VerificationBatch | undefined
    const enqueue = (item: VerifyItem): Promise<boolean> => {
      if (pending === undefined) {
        const items: Array<VerifyItem> = []
        const yields: Array<Promise<void>> = []
        const result = Promise.resolve().then(async () => {
          // Seal at this microtask, before waiting: later misses form another group.
          pending = undefined
          // Enqueue before yielding so macrotask yields cannot split an admitted group.
          await Promise.all(yields)
          const first = items[0]
          if (items.length === 1 && first !== undefined) {
            return [await crypto.verify(first.alg, first.signature, first.message, first.publicKey)]
          }
          return crypto.verifyBatch(items)
        })
        pending = { items, yields, result }
      }
      const index = pending.items.length
      pending.items.push(item)
      pending.yields.push(maybeYield())
      return pending.result.then((results) => results[index] === true)
    }
    for (const alg of ['EdDSA', 'ES256'] as const) {
      verifiers[alg] = memoizeVerifier(alg, (signature, message, publicKey) => {
        return enqueue({ alg, signature, message, publicKey })
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
