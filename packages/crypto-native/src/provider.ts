import type { CryptoAlgorithm, CryptoProvider, SignItem, VerifyItem } from '@kokuin/crypto'

import type { ByteView, Crypto, CryptoRequest } from './Crypto.nitro.js'

const EMPTY = new Uint8Array()

function view(value: Uint8Array): ByteView {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer))
    throw new TypeError('Expected an unshared Uint8Array')
  new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  return { buffer: value.buffer, offset: value.byteOffset, length: value.byteLength }
}

function algorithm(alg: CryptoAlgorithm): number {
  if (alg === 'EdDSA') return 1
  if (alg === 'ES256') return 2
  throw new TypeError('Unsupported verification algorithm')
}

function signingRequest(alg: 'EdDSA', item: SignItem): CryptoRequest {
  if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
  if (item.privateKey.length !== 32) throw new TypeError('Expected a 32-byte Ed25519 seed')
  return {
    operation: 1,
    algorithm: 1,
    key: view(item.privateKey),
    message: view(item.message),
    signature: view(EMPTY),
    outputLength: 0,
  }
}

function verifyRequest(item: VerifyItem): CryptoRequest {
  return {
    operation: 2,
    algorithm: algorithm(item.alg),
    key: view(item.publicKey),
    message: view(item.message),
    signature: view(item.signature),
    outputLength: 0,
  }
}

function hashRequest(input: Uint8Array, dkLen: number): CryptoRequest {
  if (!Number.isInteger(dkLen) || dkLen < 1 || dkLen > 65536)
    throw new RangeError('Invalid blake3 output length')
  return {
    operation: 3,
    algorithm: 0,
    key: view(EMPTY),
    message: view(input),
    signature: view(EMPTY),
    outputLength: dkLen,
  }
}

function decode(outputs: Array<ArrayBuffer>, count: number, length: number): Array<Uint8Array> {
  if (outputs.length !== count) throw new Error('Invalid native crypto response count')
  return outputs.map((buffer) => {
    if (buffer.byteLength !== length) throw new Error('Invalid native crypto response length')
    return new Uint8Array(buffer)
  })
}

function verified(bytes: Uint8Array): boolean {
  if (bytes[0] !== 0 && bytes[0] !== 1) throw new Error('Invalid native crypto response boolean')
  return bytes[0] === 1
}

export function providerFor(bridge: Pick<Crypto, 'abiVersion' | 'execute'>): CryptoProvider {
  if (bridge.abiVersion !== 1) throw new Error('Native crypto ABI mismatch')
  return {
    async sign(alg: 'EdDSA', privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
      return decode(
        await bridge.execute([signingRequest(alg, { privateKey, message })]),
        1,
        64,
      )[0] as Uint8Array
    },
    async signBatch(alg: 'EdDSA', items: Array<SignItem>): Promise<Array<Uint8Array>> {
      if (alg !== 'EdDSA') throw new TypeError('Unsupported signing algorithm')
      return decode(
        await bridge.execute(items.map((item) => signingRequest(alg, item))),
        items.length,
        64,
      )
    },
    async verify(
      alg: CryptoAlgorithm,
      signature: Uint8Array,
      message: Uint8Array,
      publicKey: Uint8Array,
    ): Promise<boolean> {
      return verified(
        decode(
          await bridge.execute([verifyRequest({ alg, signature, message, publicKey })]),
          1,
          1,
        )[0] as Uint8Array,
      )
    },
    async verifyBatch(items: Array<VerifyItem>): Promise<Array<boolean>> {
      return decode(await bridge.execute(items.map(verifyRequest)), items.length, 1).map(verified)
    },
    async blake3(input: Uint8Array, dkLen: number): Promise<Uint8Array> {
      return decode(await bridge.execute([hashRequest(input, dkLen)]), 1, dkLen)[0] as Uint8Array
    },
    async blake3Batch(inputs: Array<Uint8Array>, dkLen: number): Promise<Array<Uint8Array>> {
      hashRequest(EMPTY, dkLen)
      return decode(
        await bridge.execute(inputs.map((input) => hashRequest(input, dkLen))),
        inputs.length,
        dkLen,
      )
    },
  }
}
