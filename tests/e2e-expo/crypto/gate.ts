export type BenchmarkCell = {
  operation: 'sign' | 'verify-ed25519' | 'verify-es256' | 'blake3'
  mode: 'single' | 'batch'
  messageSize: number
  batchSize: number
  outputLength: number
  workload: 'valid' | 'invalid' | 'mixed'
  keys: 'repeated' | 'distinct'
}

export type BenchmarkSample = {
  platform: 'ios' | 'android'
  device: string
  physical: boolean
  release: boolean
  hermes: boolean
  revision: string
  backend: 'current-noble' | 'strict-noble' | 'native'
  run: number
  warmups: number
  cell: BenchmarkCell
  wallMs: Array<number>
  jsMs: Array<number>
  timerDelayMs: Array<number>
  firstCall?: { wallMs: number; jsMs: number }
}

export type GateReport = {
  status: 'pending' | 'stop' | 'proceed'
  missing: number
  issues: Array<string>
  routes: Array<{ variant: string; backend: 'native' | 'noble' }>
}

export function benchmarkCells(): Array<BenchmarkCell> {
  const cells: Array<BenchmarkCell> = []
  for (const operation of ['sign', 'verify-ed25519', 'verify-es256', 'blake3'] as const) {
    for (const mode of ['single', 'batch'] as const) {
      for (const batchSize of mode === 'single' ? [1] : [1, 8, 32, 128]) {
        for (const messageSize of [0, 32, 256, 4096, 65536]) {
          for (const outputLength of operation === 'blake3' ? [16, 32, 64] : [0]) {
            const verification = operation.startsWith('verify-')
            for (const workload of verification
              ? (['valid', 'invalid', 'mixed'] as const)
              : (['valid'] as const)) {
              for (const keys of verification
                ? (['repeated', 'distinct'] as const)
                : (['repeated'] as const)) {
                cells.push({
                  operation,
                  mode,
                  batchSize,
                  messageSize,
                  outputLength,
                  workload,
                  keys,
                })
              }
            }
          }
        }
      }
    }
  }
  return cells
}

function variant(cell: BenchmarkCell): string {
  return `${cell.operation}:${cell.mode}:${cell.batchSize}:${cell.outputLength}`
}

function cellID(cell: BenchmarkCell): string {
  return `${variant(cell)}:${cell.messageSize}:${cell.workload}:${cell.keys}`
}

function percentile(values: Array<number>, fraction: number): number {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.ceil(sorted.length * fraction) - 1] as number
}

function validTimings(values: Array<number>): boolean {
  return values.length >= 200 && values.every((value) => Number.isFinite(value) && value >= 0)
}

export function evaluateGate(samples: Array<BenchmarkSample>): GateReport {
  const cells = benchmarkCells()
  const knownCells = new Set(cells.map(cellID))
  const evidence = new Map<string, BenchmarkSample>()
  const issues: Array<string> = []
  const devices = new Map<string, string>()
  const revisions = new Set<string>()
  for (const sample of samples) {
    const key = `${sample.platform}:${sample.backend}:${sample.run}:${cellID(sample.cell)}`
    if (
      !['ios', 'android'].includes(sample.platform) ||
      !['current-noble', 'strict-noble', 'native'].includes(sample.backend) ||
      !knownCells.has(cellID(sample.cell)) ||
      !Number.isInteger(sample.run) ||
      sample.run < 0 ||
      sample.run >= 5
    ) {
      issues.push(`Unknown benchmark cell: ${key}`)
      continue
    }
    if (
      !sample.physical ||
      !sample.release ||
      !sample.hermes ||
      !sample.device.trim() ||
      !sample.revision.trim() ||
      !Number.isInteger(sample.warmups) ||
      sample.warmups < 100 ||
      !validTimings(sample.wallMs) ||
      !validTimings(sample.jsMs) ||
      !validTimings(sample.timerDelayMs) ||
      sample.wallMs.length !== sample.jsMs.length ||
      sample.wallMs.length !== sample.timerDelayMs.length
    ) {
      issues.push(`Incomplete or ineligible evidence: ${key}`)
      continue
    }
    if (evidence.has(key)) issues.push(`Duplicate evidence: ${key}`)
    const device = devices.get(sample.platform)
    if (device !== undefined && device !== sample.device)
      issues.push(`Device changed on ${sample.platform}`)
    devices.set(sample.platform, sample.device)
    revisions.add(sample.revision)
    evidence.set(key, sample)
  }
  if (revisions.size > 1) issues.push('Evidence spans different source revisions')
  const eligible = new Map<string, boolean>()
  let missing = 0
  for (const cell of cells) {
    const route = variant(cell)
    if (!eligible.has(route)) eligible.set(route, true)
    for (const platform of ['ios', 'android']) {
      for (let run = 0; run < 5; run++) {
        const get = (backend: string) =>
          evidence.get(`${platform}:${backend}:${run}:${cellID(cell)}`)
        const native = get('native')
        const noble = get('strict-noble')
        for (const backend of ['current-noble', 'strict-noble', 'native'])
          if (!get(backend)) missing++
        if (native === undefined || noble === undefined) {
          eligible.set(route, false)
        } else if (
          percentile(noble.wallMs, 0.5) <= 0 ||
          percentile(native.wallMs, 0.5) > percentile(noble.wallMs, 0.5) * 0.9 ||
          percentile(native.wallMs, 0.95) > percentile(noble.wallMs, 0.95) ||
          percentile(native.jsMs, 0.95) > percentile(noble.jsMs, 0.95)
        ) {
          eligible.set(route, false)
        }
      }
    }
  }
  const pending = missing !== 0 || issues.length !== 0
  const routes = [...eligible].map(([variant, passes]) => ({
    variant,
    backend: !pending && passes ? ('native' as const) : ('noble' as const),
  }))
  return {
    status: pending
      ? 'pending'
      : routes.some((route) => route.backend === 'native')
        ? 'proceed'
        : 'stop',
    missing,
    issues,
    routes,
  }
}
