import type { CryptoProvider } from '@kokuin/crypto'
import { NitroModules } from 'react-native-nitro-modules'

import type { Crypto } from './Crypto.nitro.js'
import { providerFor } from './provider.js'

export function createNativeCrypto(): CryptoProvider {
  return providerFor(NitroModules.createHybridObject<Crypto>('Crypto'))
}

export type { CryptoAlgorithm, CryptoProvider, SignItem, VerifyItem } from '@kokuin/crypto'

export { createNativeCrypto as createSpikeCrypto }
