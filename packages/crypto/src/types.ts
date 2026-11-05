export type CryptoAlgorithm = 'EdDSA' | 'ES256'
export type SignItem = { privateKey: Uint8Array; message: Uint8Array }
export type VerifyItem = {
  alg: CryptoAlgorithm
  signature: Uint8Array
  message: Uint8Array
  publicKey: Uint8Array
}

export type CryptoProviderSignParams = { alg: 'EdDSA'; privateKey: Uint8Array; message: Uint8Array }
export type CryptoProviderSignBatchParams = { alg: 'EdDSA'; items: Array<SignItem> }
export type CryptoProviderBlake3Params = { input: Uint8Array; dkLen: number }
export type CryptoProviderBlake3BatchParams = { inputs: Array<Uint8Array>; dkLen: number }

export type CryptoProvider = {
  sign(params: CryptoProviderSignParams): Promise<Uint8Array>
  signBatch(params: CryptoProviderSignBatchParams): Promise<Array<Uint8Array>>
  verify(params: VerifyItem): Promise<boolean>
  verifyBatch(items: Array<VerifyItem>): Promise<Array<boolean>>
  blake3(params: CryptoProviderBlake3Params): Promise<Uint8Array>
  blake3Batch(params: CryptoProviderBlake3BatchParams): Promise<Array<Uint8Array>>
}
