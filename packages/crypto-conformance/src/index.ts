import type { CryptoProvider } from '@kokuin/crypto'
import { hexToBytes } from '@noble/hashes/utils.js'

import { type CorpusVerifyCase, corpus } from './corpus.js'

export type {
  CorpusHashCase,
  CorpusInvalidSeed,
  CorpusSignCase,
  CorpusVerifyCase,
  CryptoCorpus,
} from './corpus.js'
export { corpus } from './corpus.js'

export type CryptoConformanceCase = { name: string; run(): Promise<void> }

function find<T extends { name: string }>(entries: Array<T>, name: string): T {
  const entry = entries.find((candidate) => candidate.name === name)
  if (entry == null) throw new Error(`Crypto conformance: missing corpus entry ${name}`)
  return entry
}

function verifyCase(name: string): CorpusVerifyCase {
  return find(corpus.verify, name)
}

// Batch-semantics cases reuse corpus bytes; every rejection they expect is structural
// (mutated message, empty signature), so no guard-specific vector appears in them.
const RFC = find(corpus.ed25519Sign, 'RFC 8032 test 1')
const SEED = RFC.seed
const SIGNATURE = RFC.signature
const KEY = verifyCase('Ed25519 RFC 8032 test 1').publicKey
const HASH = find(corpus.blake3, 'empty input, 64 bytes').outputPrefix
const ES_VALID = verifyCase('ES256 compact low-S')
const ES_MUTATED = verifyCase('ES256 compact low-S over a mutated message')
const ES_KEY = ES_VALID.publicKey
const ES_MESSAGE = ES_VALID.message
const ES_SIGNATURE = ES_VALID.signature

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
      name: 'batch array membership is captured before suspension',
      async run() {
        const signing = [{ privateKey: hexToBytes(SEED), message: new Uint8Array() }]
        const signed = provider.signBatch('EdDSA', signing)
        signing.length = 0
        const signatures = await signed
        assert(signatures.length === 1, 'signing batch membership changed')
        equal(signatures[0] as Uint8Array, hexToBytes(SIGNATURE))
        const item = {
          alg: 'EdDSA' as const,
          signature: hexToBytes(SIGNATURE),
          message: new Uint8Array(),
          publicKey: hexToBytes(KEY),
        }
        const verification = [item]
        const verified = provider.verifyBatch(verification)
        verification.push(item)
        const results = await verified
        assert(results.length === 1 && results[0] === true, 'verification batch membership changed')
        const inputs = [new Uint8Array()]
        const hashed = provider.blake3Batch(inputs, 16)
        inputs.pop()
        const hashes = await hashed
        assert(hashes.length === 1, 'hashing batch membership changed')
        equal(hashes[0] as Uint8Array, hexToBytes(HASH).subarray(0, 16))
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
            signature: hexToBytes(ES_MUTATED.signature),
            message: hexToBytes(ES_MUTATED.message),
            publicKey: hexToBytes(ES_MUTATED.publicKey),
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
        equal(await hashed, hexToBytes(find(corpus.blake3, 'abc, 32 bytes').outputPrefix))
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
  for (const entry of corpus.ed25519Sign) {
    cases.push({
      name: `sign: ${entry.name}`,
      async run() {
        const signature = await provider.sign(
          'EdDSA',
          hexToBytes(entry.seed),
          hexToBytes(entry.message),
        )
        equal(signature, hexToBytes(entry.signature))
      },
    })
  }
  for (const entry of corpus.ed25519InvalidSeeds) {
    cases.push({
      name: `sign rejects: ${entry.name}`,
      async run() {
        await rejects(provider.sign('EdDSA', hexToBytes(entry.seed), new Uint8Array()), TypeError)
      },
    })
  }
  for (const entry of corpus.verify) {
    cases.push({
      name: `verify: ${entry.name}`,
      async run() {
        const item = {
          alg: entry.alg,
          signature: hexToBytes(entry.signature),
          message: hexToBytes(entry.message),
          publicKey: hexToBytes(entry.publicKey),
        }
        const single = await provider.verify(item.alg, item.signature, item.message, item.publicKey)
        assert(single === entry.valid, `${entry.name}: verify returned ${single}`)
        const batch = await provider.verifyBatch([item])
        assert(
          batch.length === 1 && batch[0] === entry.valid,
          `${entry.name}: verifyBatch returned ${String(batch[0])}`,
        )
      },
    })
  }
  for (const entry of corpus.blake3) {
    cases.push({
      name: `blake3: ${entry.name}`,
      async run() {
        const input = hexToBytes(entry.input)
        const result = await provider.blake3(input, entry.length)
        assert(result.length === entry.length, 'incorrect hash length')
        const prefix = hexToBytes(entry.outputPrefix)
        equal(result.subarray(0, prefix.length), prefix)
        const batch = await provider.blake3Batch([input, input], entry.length)
        assert(batch.length === 2, 'missing hashes')
        equal(batch[0] as Uint8Array, result)
        batch[0]?.fill(0)
        equal(batch[1] as Uint8Array, result)
      },
    })
  }
  for (const length of corpus.blake3InvalidLengths) {
    cases.push({
      name: `blake3 rejects output length ${length}`,
      async run() {
        await rejects(provider.blake3(new Uint8Array(), length), RangeError)
      },
    })
  }
  return cases
}
