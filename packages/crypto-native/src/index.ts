import type { CryptoProvider } from '@kokuin/crypto'
import { NitroModules } from 'react-native-nitro-modules'

import type { Crypto } from './Crypto.nitro.js'
import { providerFor } from './provider.js'

export function createNativeCrypto(): CryptoProvider {
  if (!NitroModules.hasHybridObject('Crypto')) {
    throw new Error(
      'Native crypto is unavailable: the Nitro hybrid object "Crypto" is not registered. ' +
        'The KokuinCrypto native library is missing or failed to load, usually because this ' +
        'build targets an unsupported ABI (supported: iOS arm64 devices, arm64/x86_64 simulators; ' +
        'Android arm64-v8a and x86_64), or the app was not rebuilt after installing @kokuin/crypto-native.',
    )
  }
  return providerFor(NitroModules.createHybridObject<Crypto>('Crypto'))
}

export type { CryptoAlgorithm, CryptoProvider, SignItem, VerifyItem } from '@kokuin/crypto'
