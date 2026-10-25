import { NitroModules } from 'react-native-nitro-modules'

import type { Crypto } from './Crypto.nitro.js'
import { providerFor } from './provider.js'

export function createSpikeCrypto() {
  return providerFor(NitroModules.createHybridObject<Crypto>('Crypto'))
}
