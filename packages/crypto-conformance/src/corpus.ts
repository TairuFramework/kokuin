import type { CryptoAlgorithm } from '@kokuin/crypto'

// The same bytes are read by crates/kokuin-crypto/tests/corpus.rs. Keep the path stable.
import data from '../vectors/corpus.json' with { type: 'json' }

export type CorpusSignCase = { name: string; seed: string; message: string; signature: string }
export type CorpusInvalidSeed = { name: string; seed: string }
export type CorpusVerifyCase = {
  name: string
  alg: CryptoAlgorithm
  publicKey: string
  message: string
  signature: string
  valid: boolean
  note?: string
  /** Deliberately weakened verifiers, per backend, that accept this rejected vector. */
  weakenedBy?: { noble: Array<string>; rust: Array<string> }
}
export type CorpusHashCase = { name: string; input: string; length: number; outputPrefix: string }

export type CryptoCorpus = {
  description: string
  ed25519Sign: Array<CorpusSignCase>
  ed25519InvalidSeeds: Array<CorpusInvalidSeed>
  verify: Array<CorpusVerifyCase>
  blake3: Array<CorpusHashCase>
  blake3InvalidLengths: Array<number>
}

export const corpus: CryptoCorpus = data as CryptoCorpus
