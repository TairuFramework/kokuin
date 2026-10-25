import { expect, test } from 'vitest'

import { type BenchmarkSample, benchmarkCells, evaluateGate } from './gate.js'

function completeSamples(nativeWall = 0.5): Array<BenchmarkSample> {
  const times = (value: number) => Array<number>(200).fill(value)
  const baseline = times(1)
  const native = times(nativeWall)
  const samples: Array<BenchmarkSample> = []
  for (const platform of ['ios', 'android'] as const) {
    for (const cell of benchmarkCells()) {
      for (let run = 0; run < 5; run++) {
        for (const backend of ['current-noble', 'strict-noble', 'native'] as const) {
          samples.push({
            platform,
            cell,
            run,
            backend,
            device: `${platform}-phone`,
            physical: true,
            release: true,
            hermes: true,
            revision: 'test-revision',
            warmups: 100,
            wallMs: backend === 'native' ? native : baseline,
            jsMs: backend === 'native' ? native : baseline,
            timerDelayMs: baseline,
          })
        }
      }
    }
  }
  return samples
}

test('requires every planned message size, batch mode and verification workload', () => {
  const cells = benchmarkCells()
  expect(new Set(cells.map((cell) => cell.messageSize))).toEqual(new Set([0, 32, 256, 4096, 65536]))
  expect(cells.some((cell) => cell.mode === 'single' && cell.batchSize === 1)).toBe(true)
  expect(cells.some((cell) => cell.mode === 'batch' && cell.batchSize === 1)).toBe(true)
  expect(cells.some((cell) => cell.workload === 'mixed' && cell.keys === 'distinct')).toBe(true)
})

test('missing platforms, runs and insufficient samples leave the gate pending', () => {
  expect(evaluateGate([]).status).toBe('pending')
  const samples = completeSamples()
  expect(evaluateGate(samples.filter((sample) => sample.platform === 'ios')).status).toBe('pending')
  expect(evaluateGate(samples.filter((sample) => sample.run !== 4)).status).toBe('pending')
  samples[0] = { ...(samples[0] as BenchmarkSample), wallMs: [1] }
  expect(evaluateGate(samples).status).toBe('pending')
})

test('complete measurements proceed only for consistent improvements on both devices', () => {
  const report = evaluateGate(completeSamples())
  expect(report.status).toBe('proceed')
  expect(report.missing).toBe(0)
  expect(report.routes.every((route) => route.backend === 'native')).toBe(true)
})

test('complete failure stops and a noisy final run cannot qualify a route', () => {
  expect(evaluateGate(completeSamples(1)).status).toBe('stop')
  const noisy = completeSamples().map((sample) =>
    sample.backend === 'native' && sample.run === 4
      ? { ...sample, wallMs: Array<number>(200).fill(0.95) }
      : sample,
  )
  expect(evaluateGate(noisy).status).toBe('stop')
})

test('batch-only wins retain noble for single calls', () => {
  const samples = completeSamples().map((sample) =>
    sample.backend === 'native' && sample.cell.mode === 'single'
      ? { ...sample, wallMs: Array<number>(200).fill(1) }
      : sample,
  )
  const report = evaluateGate(samples)
  expect(report.status).toBe('proceed')
  expect(
    report.routes
      .filter((route) => route.variant.includes(':single:'))
      .every((route) => route.backend === 'noble'),
  ).toBe(true)
  expect(
    report.routes
      .filter((route) => route.variant.includes(':batch:'))
      .every((route) => route.backend === 'native'),
  ).toBe(true)
})

test('simulators, debug builds, duplicates and invalid timings cannot provide gate evidence', () => {
  const samples = completeSamples()
  for (const patch of [
    { physical: false },
    { release: false },
    { hermes: false },
    { wallMs: Array<number>(200).fill(Number.NaN) },
  ]) {
    expect(
      evaluateGate([{ ...(samples[0] as BenchmarkSample), ...patch }, ...samples.slice(1)]).status,
    ).toBe('pending')
  }
  expect(evaluateGate([...samples, samples[0] as BenchmarkSample]).status).toBe('pending')
})
