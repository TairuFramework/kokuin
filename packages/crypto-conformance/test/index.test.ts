import { type CryptoAlgorithm, type CryptoProvider, nobleCrypto } from '@kokuin/crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import {
  bytesToNumberBE,
  bytesToNumberLE,
  numberToBytesBE,
  numberToBytesLE,
} from '@noble/curves/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes, hexToBytes } from '@noble/hashes/utils.js'
import { describe, expect, test } from 'vitest'

import { corpus, cryptoConformance, externalConformance, externalVectors } from '../src/index.js'

type CheckParams = {
  alg: CryptoAlgorithm
  signature: Uint8Array
  message: Uint8Array
  publicKey: Uint8Array
}

test('runs the complete provider contract against strict noble', async () => {
  for (const entry of cryptoConformance(nobleCrypto)) await entry.run()
})

test('rejects a provider which accepts every verification input', async () => {
  const incorrect = {
    ...nobleCrypto,
    verify: async () => true,
    verifyBatch: async (items: Array<unknown>) => items.map(() => true),
  }
  const outcomes = await Promise.allSettled(
    cryptoConformance(incorrect).map((entry) => entry.run()),
  )
  expect(outcomes.some((entry) => entry.status === 'rejected')).toBe(true)
})

test('rejects a provider which returns the wrong hash', async () => {
  const incorrect = {
    ...nobleCrypto,
    blake3: async (_input: Uint8Array, length: number) => new Uint8Array(length),
  }
  const outcomes = await Promise.allSettled(
    cryptoConformance(incorrect).map((entry) => entry.run()),
  )
  expect(outcomes.some((entry) => entry.status === 'rejected')).toBe(true)
})

// Each weakened verifier is strict noble (packages/crypto/src/noble.ts) with exactly one guard
// removed. The corpus records which vectors each one must let through (`weakenedBy.noble`).
type Verify = (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean

const L = ed25519.Point.Fn.ORDER
const N = p256.Point.Fn.ORDER

function strictPoint(bytes: Uint8Array): boolean {
  const point = ed25519.Point.fromBytes(bytes, false)
  return !point.isSmallOrder() && point.isTorsionFree()
}

function es256Key(publicKey: Uint8Array): boolean {
  return (
    (publicKey.length === 33 && (publicKey[0] === 2 || publicKey[0] === 3)) ||
    (publicKey.length === 65 && publicKey[0] === 4)
  )
}

function guarded(verify: Verify): Verify {
  return (signature, message, publicKey) => {
    if (signature.length !== 64) return false
    try {
      return verify(signature, message, publicKey)
    } catch {
      return false
    }
  }
}

function strictEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) {
  return (
    publicKey.length === 32 &&
    strictPoint(publicKey) &&
    strictPoint(signature.subarray(0, 32)) &&
    ed25519.verify(signature, message, publicKey, { zip215: false })
  )
}

function strictEs256(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) {
  return (
    es256Key(publicKey) &&
    p256.verify(signature, message, publicKey, { lowS: true, prehash: true, format: 'compact' })
  )
}

const weakenings: Record<string, { alg: CryptoAlgorithm; verify: Verify }> = {
  'subgroup-a': {
    alg: 'EdDSA',
    verify: (signature, message, publicKey) => {
      return (
        publicKey.length === 32 &&
        strictPoint(signature.subarray(0, 32)) &&
        ed25519.verify(signature, message, publicKey, { zip215: false })
      )
    },
  },
  'subgroup-r': {
    alg: 'EdDSA',
    verify: (signature, message, publicKey) => {
      return (
        publicKey.length === 32 &&
        strictPoint(publicKey) &&
        ed25519.verify(signature, message, publicKey, { zip215: false })
      )
    },
  },
  's-range': {
    alg: 'EdDSA',
    verify: (signature, message, publicKey) => {
      const s = bytesToNumberLE(signature.subarray(32)) % L
      const reduced = concatBytes(signature.subarray(0, 32), numberToBytesLE(s, 32))
      return strictEd25519(reduced, message, publicKey)
    },
  },
  'low-s': {
    alg: 'ES256',
    verify: (signature, message, publicKey) => {
      return (
        es256Key(publicKey) &&
        p256.verify(signature, message, publicKey, {
          lowS: false,
          prehash: true,
          format: 'compact',
        })
      )
    },
  },
  'scalar-range': {
    alg: 'ES256',
    verify: (signature, message, publicKey) => {
      const r = bytesToNumberBE(signature.subarray(0, 32)) % N
      const s = bytesToNumberBE(signature.subarray(32)) % N
      return strictEs256(
        concatBytes(numberToBytesBE(r, 32), numberToBytesBE(s, 32)),
        message,
        publicKey,
      )
    },
  },
  // Hand-written ECDSA keeping every check except r, s != 0, with the CVE-2022-21449 inverse.
  'zero-scalars': {
    alg: 'ES256',
    verify: (signature, message, publicKey) => {
      if (!es256Key(publicKey)) return false
      const Fn = p256.Point.Fn
      const r = bytesToNumberBE(signature.subarray(0, 32))
      const s = bytesToNumberBE(signature.subarray(32))
      if (r >= N || s >= N || s > N >> 1n) return false
      const key = p256.Point.fromBytes(publicKey)
      const h = bytesToNumberBE(sha256(message)) % N
      const w = Fn.pow(s, N - 2n)
      const point = p256.Point.BASE.multiplyUnsafe(Fn.mul(h, w)).add(
        key.multiplyUnsafe(Fn.mul(r, w)),
      )
      return (point.is0() ? 0n : point.toAffine().x % N) === r
    },
  },
}

function weakened(name: string): CryptoProvider {
  const weakening = weakenings[name]
  if (weakening == null) throw new Error(`No weakened verifier ${name}`)
  const verify = guarded(weakening.verify)
  const check = ({ alg, signature, message, publicKey }: CheckParams) => {
    return alg === weakening.alg
      ? Promise.resolve(verify(signature, message, publicKey))
      : nobleCrypto.verify({
          alg: alg,
          signature: signature,
          message: message,
          publicKey: publicKey,
        })
  }
  return {
    ...nobleCrypto,
    verify: check,
    verifyBatch: (items) => {
      return Promise.all(
        items.map((item) => {
          return check({
            alg: item.alg,
            signature: item.signature,
            message: item.message,
            publicKey: item.publicKey,
          })
        }),
      )
    },
  }
}

describe('each guard is certified by its own corpus vectors', () => {
  test('the reference re-implementations match strict noble on the corpus', () => {
    for (const entry of corpus.verify) {
      const bytes = [entry.signature, entry.message, entry.publicKey].map(hexToBytes) as [
        Uint8Array,
        Uint8Array,
        Uint8Array,
      ]
      const strict = guarded(entry.alg === 'EdDSA' ? strictEd25519 : strictEs256)
      expect(strict(...bytes), entry.name).toBe(entry.valid)
    }
  })

  test('every noble weakening named by the corpus is implemented', () => {
    const named = new Set(corpus.verify.flatMap((entry) => entry.weakenedBy?.noble ?? []))
    expect([...named].sort()).toEqual(Object.keys(weakenings).sort())
  })

  for (const name of Object.keys(weakenings)) {
    test(`removing ${name} fails exactly the vectors that certify it`, async () => {
      const expected = corpus.verify
        .filter((entry) => entry.weakenedBy?.noble.includes(name))
        .map((entry) => `verify: ${entry.name}`)
      expect(expected.length).toBeGreaterThan(0)
      const cases = cryptoConformance(weakened(name))
      const outcomes = await Promise.allSettled(cases.map((entry) => entry.run()))
      const failures = cases.flatMap((entry, index) => {
        const outcome = outcomes[index]
        return outcome?.status === 'rejected'
          ? [{ name: entry.name, message: String(outcome.reason) }]
          : []
      })
      expect(failures.map((failure) => failure.name).sort()).toEqual(expected.sort())
      // A forgery is accepted, rather than some unrelated assertion tripping.
      for (const failure of failures) expect(failure.message).toContain('verify returned true')
    })
  }
})

// Each test runs about a thousand strict-noble operations: about 2s locally, and CI runners under
// load have been up to 20 times slower.
describe('pinned upstream vectors', { timeout: 120_000 }, () => {
  test('strict noble passes every external vector', async () => {
    for (const entry of externalConformance(nobleCrypto)) await entry.run()
  })

  test('every expected outcome follows the upstream verdict and the documented policy', () => {
    for (const entry of externalVectors.verify) {
      const highS = entry.flags.includes('HighS')
      // `acceptable` Wycheproof Ed25519 vectors use small-order or mixed-order keys; the
      // contract rejects them. High-S ES256 signatures are rejected as malleable.
      expect(entry.valid, `${entry.source}/${entry.id}`).toBe(entry.upstream === 'valid' && !highS)
    }
  })

  test('a signer or hash with wrong output fails its external case', async () => {
    const wrong = {
      ...nobleCrypto,
      sign: async () => new Uint8Array(64),
      blake3: async (_input: Uint8Array, length: number) => new Uint8Array(length),
    }
    const cases = externalConformance(wrong)
    const outcomes = await Promise.allSettled(cases.map((entry) => entry.run()))
    const failed = cases.filter((_, index) => outcomes[index]?.status === 'rejected')
    expect(failed.map((entry) => entry.name).sort()).toEqual([
      'external blake3: blake3-official',
      'external sign: supercop-ed25519 (includes RFC 8032 TEST 1-3)',
    ])
  })

  // Which upstream set catches each single-guard weakening. Wycheproof has no Ed25519 vector with
  // a torsioned R and a torsion-free A, so only the hand-written corpus certifies subgroup-r.
  const caughtBy: Record<string, string | null> = {
    'subgroup-a': 'wycheproof-ed25519',
    'subgroup-r': null,
    's-range': 'wycheproof-ed25519',
    'low-s': 'wycheproof-ecdsa-p256',
    'scalar-range': 'wycheproof-ecdsa-p256',
    'zero-scalars': 'wycheproof-ecdsa-p256',
  }

  test('the table covers every weakening', () => {
    expect(Object.keys(caughtBy).sort()).toEqual(Object.keys(weakenings).sort())
  })

  for (const [name, source] of Object.entries(caughtBy)) {
    test(`removing ${name} is ${source == null ? 'not caught' : `caught by ${source}`}`, async () => {
      const cases = externalConformance(weakened(name))
      const outcomes = await Promise.allSettled(cases.map((entry) => entry.run()))
      const failures = cases.flatMap((entry, index) => {
        const outcome = outcomes[index]
        return outcome?.status === 'rejected'
          ? [{ name: entry.name, message: String(outcome.reason) }]
          : []
      })
      expect(failures.map((failure) => failure.name)).toEqual(
        source == null ? [] : [`external verify: ${source}`],
      )
      for (const failure of failures) {
        expect(failure.message).toContain('returned true')
        expect(failure.message).not.toContain('returned false')
      }
    })
  }
})
