import type { HybridObject } from 'react-native-nitro-modules'

export type ByteView = { buffer: ArrayBuffer; offset: number; length: number }
export type CryptoRequest = {
  operation: number
  algorithm: number
  key: ByteView
  message: ByteView
  signature: ByteView
  outputLength: number
}

// Nitrogen requires interface declarations for Hybrid Objects.
export interface Crypto extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  readonly abiVersion: number
  execute(requests: Array<CryptoRequest>): Promise<Array<ArrayBuffer>>
}
