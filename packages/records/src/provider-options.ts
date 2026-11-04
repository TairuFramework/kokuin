import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import type { CryptoOptions, MethodRegistry } from '@kokuin/token'

export function captureMethods(methods?: MethodRegistry): MethodRegistry | undefined {
  return methods?.map((method) => ({
    ...method,
    method: method.method,
    resolve: method.resolve.bind(method),
    resolveHistoric: method.resolveHistoric?.bind(method),
  }))
}

export class ProviderFailure extends Error {}
const guardedProviders = new WeakMap<CryptoProvider, CryptoProvider>()
const sources = new WeakMap<CryptoProvider, CryptoProvider>()

/** Guard refusal catches without changing the identity of the memo policy. */
export function providerSource(crypto: CryptoProvider): CryptoProvider {
  return sources.get(crypto) ?? crypto
}

export function guardedProvider(crypto: CryptoProvider): CryptoProvider {
  let guarded = guardedProviders.get(crypto)
  if (guarded === undefined) {
    guarded = {
      ...crypto,
      async verify(...args) {
        try {
          return await crypto.verify(...args)
        } catch (cause) {
          throw new ProviderFailure('Crypto provider failed', { cause })
        }
      },
      async verifyBatch(items) {
        try {
          return await crypto.verifyBatch(items)
        } catch (cause) {
          throw new ProviderFailure('Crypto provider failed', { cause })
        }
      },
      async blake3(...args) {
        try {
          return await crypto.blake3(...args)
        } catch (cause) {
          throw new ProviderFailure('Crypto provider failed', { cause })
        }
      },
    }
    guardedProviders.set(crypto, guarded)
    sources.set(guarded, providerSource(crypto))
  }
  return guarded
}

export function captureOptions(options?: CryptoOptions): { crypto: CryptoProvider } {
  return { crypto: options?.crypto ?? nobleCrypto }
}
