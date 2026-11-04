import { type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import type { KeyStore } from '@kokuin/token'
import { createFullIdentity, type FullIdentity, type IdentityProvider } from '@kokuin/token'
import { mnemonicToSeedSync } from '@scure/bip39'
import { getLogger } from '@sozai/log'
import { withSpan } from '@sozai/otel'

import { resolveDerivationPath } from './derivation.js'
import { HDKeyEntry } from './entry.js'

const DEFAULT_BASE_PATH = "44'/876'"
const tracer = createTracer('keystore.hd')
const logger = getLogger(['kokuin', 'deterministic'])

export type HDKeyStoreParams = {
  seed: Uint8Array
  crypto?: CryptoProvider
  basePath?: string
}

export class HDKeyStore
  implements KeyStore<Uint8Array, HDKeyEntry>, IdentityProvider<FullIdentity>
{
  #seed: Uint8Array
  #basePath: string
  #crypto: CryptoProvider
  #entries: Record<string, HDKeyEntry> = Object.create(null)

  static fromMnemonic(
    mnemonic: string,
    options?: { basePath?: string; crypto?: CryptoProvider },
  ): HDKeyStore {
    const seed = mnemonicToSeedSync(mnemonic)
    return new HDKeyStore({ seed, basePath: options?.basePath, crypto: options?.crypto })
  }

  static fromSeed(
    seed: Uint8Array,
    options?: { basePath?: string; crypto?: CryptoProvider },
  ): HDKeyStore {
    return new HDKeyStore({ seed, basePath: options?.basePath, crypto: options?.crypto })
  }

  constructor(params: HDKeyStoreParams) {
    this.#crypto = params.crypto ?? nobleCrypto
    this.#seed = params.seed
    this.#basePath = params.basePath ?? DEFAULT_BASE_PATH
  }

  entry(keyID: string): HDKeyEntry {
    this.#entries[keyID] ??= new HDKeyEntry({
      seed: this.#seed,
      keyID,
      path: resolveDerivationPath(keyID, this.#basePath),
    })
    return this.#entries[keyID]
  }

  async provideIdentity(keyID: string): Promise<FullIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'hd' } },
      async (span) => {
        const entry = this.entry(keyID)
        const privateKey = await entry.provideAsync()
        const identity = createFullIdentity(privateKey, { crypto: this.#crypto })
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        logger.info('HD identity derived: {did}', { did: identity.id })
        return identity
      },
    )
  }
}
