import { expect, test } from 'vitest'

import { type BenchmarkMetadata, runBenchmarkMatrix } from './benchmark.js'
import { type BenchmarkCell, type BenchmarkSample, evaluateGate } from './gate.js'
import { strictNoble } from './strict-noble.js'

const metadata: BenchmarkMetadata = {
  platform: 'ios',
  device: 'host test',
  physical: false,
  release: false,
  hermes: false,
  revision: 'test-revision',
}
const cell: BenchmarkCell = {
  operation: 'blake3',
  mode: 'single',
  messageSize: 0,
  batchSize: 1,
  outputLength: 32,
  workload: 'valid',
  keys: 'repeated',
}

test('collects complete timing rows without treating host measurements as device evidence', async () => {
  const samples: Array<BenchmarkSample> = []
  await runBenchmarkMatrix({
    native: strictNoble,
    metadata,
    signal: new AbortController().signal,
    cells: [cell],
    async onSample(sample, completed, total) {
      samples.push(sample)
      expect(completed).toBe(samples.length)
      expect(total).toBe(15)
    },
  })
  expect(samples).toHaveLength(15)
  for (const backend of ['current-noble', 'strict-noble', 'native']) {
    expect(
      samples.filter((sample) => sample.backend === backend).map((sample) => sample.run),
    ).toEqual([0, 1, 2, 3, 4])
  }
  for (const sample of samples) {
    expect(sample.wallMs).toHaveLength(200)
    expect(sample.jsMs).toHaveLength(200)
    expect(sample.timerDelayMs).toHaveLength(200)
    expect(sample.wallMs.every((value) => Number.isFinite(value) && value >= 0)).toBe(true)
    expect(sample.firstCall?.wallMs).toBeGreaterThanOrEqual(0)
  }
  expect(evaluateGate(samples).status).toBe('pending')
}, 30000)

test('cancellation stops measurement before another row is delivered', async () => {
  const controller = new AbortController()
  const samples: Array<BenchmarkSample> = []
  await expect(
    runBenchmarkMatrix({
      native: strictNoble,
      metadata,
      signal: controller.signal,
      cells: [cell],
      async onSample(sample) {
        samples.push(sample)
        controller.abort()
      },
    }),
  ).rejects.toMatchObject({ name: 'AbortError' })
  expect(samples).toHaveLength(1)
}, 30000)
