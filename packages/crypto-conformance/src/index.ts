import type { CryptoProvider } from '@kokuin/crypto'
import { hexToBytes } from '@noble/hashes/utils.js'

import { mixedOrderVectors } from './adversarial.js'

export type CryptoConformanceCase = { name: string; run(): Promise<void> }

const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
const SIGNATURE =
  'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
const HASH =
  'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a'
const ES_KEY = '036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
const ES_MESSAGE = '6b6f6b75696e2063727970746f207370696b65'
const ES_SIGNATURE =
  'd8993d42f5ff5aaf214a10145e5f9ad8bd572acd022d87bd4d8bf989319619e1205bca699914f7f3319fd760301ff494ef95a793ed79c534bab8fbdfcdbcbd58'
const ES_HIGH =
  'd8993d42f5ff5aaf214a10145e5f9ad8bd572acd022d87bd4d8bf989319619e1dfa4359566eb080dce60289fcfe00b6acd515319b99dd9503900cee32ea667f9'

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`Crypto conformance: ${message}`)
}

function equal(actual: Uint8Array, expected: Uint8Array): void {
  assert(
    actual.length === expected.length && actual.every((value, index) => value === expected[index]),
    'unexpected bytes',
  )
}

async function rejects(operation: Promise<unknown>, errorType: typeof TypeError): Promise<void> {
  try {
    await operation
  } catch (error) {
    assert(error instanceof errorType, `expected ${errorType.name}`)
    return
  }
  throw new Error(`Crypto conformance: expected ${errorType.name} rejection`)
}

export function cryptoConformance(provider: CryptoProvider): Array<CryptoConformanceCase> {
  const cases: Array<CryptoConformanceCase> = [
    {
      name: 'RFC 8032 signing and verification',
      async run() {
        const message = new Uint8Array()
        equal(await provider.sign('EdDSA', hexToBytes(SEED), message), hexToBytes(SIGNATURE))
        assert(
          await provider.verify('EdDSA', hexToBytes(SIGNATURE), message, hexToBytes(KEY)),
          'valid Ed25519',
        )
        assert(
          !(await provider.verify(
            'EdDSA',
            hexToBytes(SIGNATURE),
            new Uint8Array([1]),
            hexToBytes(KEY),
          )),
          'mutated message accepted',
        )
      },
    },
    {
      name: 'compact P-256 verifies raw messages and rejects high-S',
      async run() {
        const message = hexToBytes(ES_MESSAGE)
        const key = hexToBytes(ES_KEY)
        assert(
          await provider.verify('ES256', hexToBytes(ES_SIGNATURE), message, key),
          'valid P-256',
        )
        assert(
          !(await provider.verify('ES256', hexToBytes(ES_HIGH), message, key)),
          'high-S accepted',
        )
        assert(
          !(await provider.verify('ES256', new Uint8Array(64), message, key)),
          'zero r/s accepted',
        )
      },
    },
    {
      name: 'mixed verification batches preserve order',
      async run() {
        const results = await provider.verifyBatch([
          {
            alg: 'EdDSA',
            signature: hexToBytes(SIGNATURE),
            message: new Uint8Array(),
            publicKey: hexToBytes(KEY),
          },
          {
            alg: 'EdDSA',
            signature: new Uint8Array(),
            message: new Uint8Array(),
            publicKey: hexToBytes(KEY),
          },
          {
            alg: 'ES256',
            signature: hexToBytes(ES_HIGH),
            message: hexToBytes(ES_MESSAGE),
            publicKey: hexToBytes(ES_KEY),
          },
          {
            alg: 'ES256',
            signature: hexToBytes(ES_SIGNATURE),
            message: hexToBytes(ES_MESSAGE),
            publicKey: hexToBytes(ES_KEY),
          },
        ])
        assert(
          results.length === 4 &&
            results[0] === true &&
            results[1] === false &&
            results[2] === false &&
            results[3] === true,
          'batch order or verification changed',
        )
      },
    },
    {
      name: 'single calls snapshot offset views',
      async run() {
        const seed = new Uint8Array(40)
        seed.set(hexToBytes(SEED), 4)
        const signed = provider.sign('EdDSA', seed.subarray(4, 36), new Uint8Array())
        seed.fill(0)
        equal(await signed, hexToBytes(SIGNATURE))
        const signature = new Uint8Array(72)
        signature.set(hexToBytes(ES_SIGNATURE), 4)
        const message = hexToBytes(ES_MESSAGE)
        const key = hexToBytes(ES_KEY)
        const verified = provider.verify('ES256', signature.subarray(4, 68), message, key)
        signature.fill(0)
        message.fill(0)
        key.fill(0)
        assert(await verified, 'verification read caller mutations')
        const input = new Uint8Array([0, 97, 98, 99, 0])
        const hashed = provider.blake3(input.subarray(1, 4), 32)
        input.fill(0)
        equal(
          await hashed,
          hexToBytes('6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'),
        )
      },
    },
    {
      name: 'signing batches snapshot inputs and own each output',
      async run() {
        const seed = hexToBytes(SEED)
        const operation = provider.signBatch('EdDSA', [
          { privateKey: seed, message: new Uint8Array() },
          { privateKey: seed, message: new Uint8Array() },
        ])
        seed.fill(0)
        const result = await operation
        assert(result.length === 2, 'missing signatures')
        equal(result[0] as Uint8Array, hexToBytes(SIGNATURE))
        result[0]?.fill(0)
        equal(result[1] as Uint8Array, hexToBytes(SIGNATURE))
      },
    },
    {
      name: 'invalid signing batches reject',
      async run() {
        await rejects(
          provider.signBatch('EdDSA', [
            { privateKey: hexToBytes(SEED), message: new Uint8Array() },
            { privateKey: new Uint8Array(31), message: new Uint8Array() },
          ]),
          TypeError,
        )
        await rejects(provider.signBatch('ES256' as 'EdDSA', []), TypeError)
      },
    },
    {
      name: 'empty batches preserve argument validation',
      async run() {
        assert((await provider.signBatch('EdDSA', [])).length === 0, 'empty signing batch')
        assert((await provider.verifyBatch([])).length === 0, 'empty verification batch')
        assert((await provider.blake3Batch([], 32)).length === 0, 'empty hashing batch')
        for (const length of [0, -1, 1.5, 65537, Number.NaN]) {
          await rejects(provider.blake3Batch([], length), RangeError)
        }
      },
    },
  ]
  for (const length of [1, 16, 32, 64, 65536]) {
    cases.push({
      name: `blake3 output length ${length}`,
      async run() {
        const result = await provider.blake3(new Uint8Array(), length)
        assert(result.length === length, 'incorrect hash length')
        equal(result.subarray(0, Math.min(length, 64)), hexToBytes(HASH).subarray(0, length))
        const batch = await provider.blake3Batch([new Uint8Array(), new Uint8Array()], length)
        assert(batch.length === 2, 'missing hashes')
        equal(batch[0] as Uint8Array, result)
        batch[0]?.fill(0)
        equal(batch[1] as Uint8Array, result)
      },
    })
  }
  for (const vector of mixedOrderVectors) {
    cases.push({
      name: `rejects ${vector.name}`,
      async run() {
        assert(
          !(await provider.verify(
            'EdDSA',
            hexToBytes(vector.signature),
            hexToBytes(vector.message),
            hexToBytes(vector.publicKey),
          )),
          'mixed-order forgery accepted',
        )
      },
    })
  }
  return cases
}
