export type CryptoAlgorithm = 'EdDSA' | 'ES256'
export type SignItem = { privateKey: Uint8Array; message: Uint8Array }
export type VerifyItem = {
  alg: CryptoAlgorithm
  signature: Uint8Array
  message: Uint8Array
  publicKey: Uint8Array
}

export type SpikeCrypto = {
  sign(alg: 'EdDSA', privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>
  signBatch(alg: 'EdDSA', items: Array<SignItem>): Promise<Array<Uint8Array>>
  verify(
    alg: CryptoAlgorithm,
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): Promise<boolean>
  verifyBatch(items: Array<VerifyItem>): Promise<Array<boolean>>
  blake3(input: Uint8Array, dkLen: number): Promise<Uint8Array>
  blake3Batch(inputs: Array<Uint8Array>, dkLen: number): Promise<Array<Uint8Array>>
}
