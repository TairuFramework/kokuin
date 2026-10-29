import type { CryptoProvider, VerifyItem } from '@kokuin/crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { blake3 } from '@noble/hashes/blake3.js'

import { type BenchmarkCell, type BenchmarkSample, benchmarkCells } from './gate'
import { strictNoble } from './strict-noble'

export type BenchmarkMetadata = Pick<
  BenchmarkSample,
  'platform' | 'device' | 'physical' | 'release' | 'hermes' | 'revision'
>
export type BenchmarkOptions = {
  native: CryptoProvider
  metadata: BenchmarkMetadata
  signal: AbortSignal
  onSample(sample: BenchmarkSample, completed: number, total: number): Promise<void>
  cells?: Array<BenchmarkCell>
}

// This comparison preserves today's noble verification rules, independently of the strict gate baseline.
const currentNoble: CryptoProvider = {
  ...strictNoble,
  async verify(alg, signature, message, publicKey) {
    try {
      return alg === 'EdDSA'
        ? ed25519.verify(signature, message, publicKey)
        : p256.verify(signature, message, publicKey, { lowS: true })
    } catch {
      return false
    }
  },
  async verifyBatch(items) {
    return items.map((item) => {
      try {
        return item.alg === 'EdDSA'
          ? ed25519.verify(item.signature, item.message, item.publicKey)
          : p256.verify(item.signature, item.message, item.publicKey, { lowS: true })
      } catch {
        return false
      }
    })
  },
  async blake3(input, dkLen) {
    return blake3(input, { dkLen })
  },
  async blake3Batch(inputs, dkLen) {
    return inputs.map((input) => blake3(input, { dkLen }))
  },
}

function prepare(
  cell: BenchmarkCell,
  provider: CryptoProvider,
): (iteration: number) => Promise<unknown> {
  const message = new Uint8Array(cell.messageSize).fill(0x61)
  const seeds = Array.from({ length: cell.batchSize }, (_, index) => {
    const seed = new Uint8Array(32)
    seed[31] = cell.keys === 'distinct' ? index + 1 : 1
    return seed
  })
  if (cell.operation === 'sign') {
    const items = seeds.map((privateKey) => ({ privateKey, message }))
    return cell.mode === 'single'
      ? () => provider.sign('EdDSA', seeds[0] as Uint8Array, message)
      : () => provider.signBatch('EdDSA', items)
  }
  if (cell.operation === 'blake3') {
    const inputs = seeds.map(() => message)
    return cell.mode === 'single'
      ? () => provider.blake3(message, cell.outputLength)
      : () => provider.blake3Batch(inputs, cell.outputLength)
  }
  const alg = cell.operation === 'verify-ed25519' ? 'EdDSA' : 'ES256'
  const curve = alg === 'EdDSA' ? ed25519 : p256
  const valid: Array<VerifyItem> = seeds.map((seed) => ({
    alg,
    message,
    publicKey: curve.getPublicKey(seed),
    signature: curve.sign(message, seed),
  }))
  const invalid = valid.map((item) => {
    const signature = item.signature.slice()
    signature[0] = (signature[0] as number) ^ 1
    return { ...item, signature }
  })
  const mixed = valid.map((item, index) =>
    index % 2 === 0 ? item : (invalid[index] as VerifyItem),
  )
  const items = cell.workload === 'invalid' ? invalid : cell.workload === 'mixed' ? mixed : valid
  return (iteration) => {
    const item =
      cell.workload === 'mixed' && cell.batchSize === 1 && iteration % 2 === 1
        ? (invalid[0] as VerifyItem)
        : (items[0] as VerifyItem)
    return cell.mode === 'single'
      ? provider.verify(item.alg, item.signature, item.message, item.publicKey)
      : provider.verifyBatch(cell.batchSize === 1 ? [item] : items)
  }
}

function pause(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0))
}

export async function runBenchmarkMatrix(options: BenchmarkOptions): Promise<void> {
  const backends = {
    'current-noble': currentNoble,
    'strict-noble': strictNoble,
    native: options.native,
  }
  const cells = options.cells ?? benchmarkCells()
  const total = cells.length * 5 * 3
  let completed = 0
  for (const cell of cells) {
    const calls = new Map(
      Object.entries(backends).map(([backend, provider]) => [backend, prepare(cell, provider)]),
    )
    for (let run = 0; run < 5; run++) {
      const order: Array<keyof typeof backends> = ['current-noble', 'strict-noble', 'native']
      // Rotate both run and cell order to distribute warm-up and thermal bias.
      const rotation = (run + cells.indexOf(cell)) % order.length
      order.push(...order.splice(0, rotation))
      for (const backend of order) {
        const call = calls.get(backend) as (iteration: number) => Promise<unknown>
        const firstStarted = performance.now()
        const firstPending = call(0)
        const firstReturned = performance.now()
        await firstPending
        const firstCall = {
          wallMs: performance.now() - firstStarted,
          jsMs: firstReturned - firstStarted,
        }
        await pause()
        for (let iteration = 0; iteration < 100; iteration++) {
          options.signal.throwIfAborted()
          await call(iteration)
          await pause()
        }
        const wallMs: Array<number> = []
        const jsMs: Array<number> = []
        const timerDelayMs: Array<number> = []
        for (let iteration = 0; iteration < 200; iteration++) {
          options.signal.throwIfAborted()
          const started = performance.now()
          const heartbeat = new Promise<number>((resolve) =>
            setTimeout(() => resolve(performance.now() - started), 0),
          )
          const pending = call(iteration)
          const returned = performance.now()
          await pending
          wallMs.push(performance.now() - started)
          jsMs.push(returned - started)
          timerDelayMs.push(await heartbeat)
        }
        await options.onSample(
          {
            ...options.metadata,
            backend,
            run,
            warmups: 100,
            cell,
            wallMs,
            jsMs,
            timerDelayMs,
            firstCall,
          },
          ++completed,
          total,
        )
        await pause()
      }
    }
  }
}
