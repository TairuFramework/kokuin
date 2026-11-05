// Node crypto benchmark gate: times @kokuin/crypto-napi against @kokuin/crypto-node (its fallback)
// on this host, with strict noble as context, and decides whether each native route pays off.
//
//   node scripts/bench-crypto-node.mjs [--out report.json] [--runs 5] [--quick]
//
// Build first: `pnpm --filter @kokuin/crypto-napi... build` and `pnpm --filter @kokuin/crypto-napi run build:native`.
//
// A run passes when crypto-napi's median wall time is at least 10% below nodeCrypto's and its p95 is
// at most 10% (plus 20 µs) above nodeCrypto's, allowing for GC and timer noise on shared runners. A cell passes when all but at most one run pass
// and the median across runs passes too, so one outlier run on a shared runner cannot flip a route. Cells crypto-napi routes to nodeCrypto (all ES256 verification) are
// reported but not gated. The report is a JSON file; with GITHUB_STEP_SUMMARY set, a table is appended there.
// The process exits 1 when any gated cell fails.
import assert from 'node:assert/strict'
import { appendFileSync, writeFileSync } from 'node:fs'
import { arch, cpus, platform } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const { values } = parseArgs({
  options: {
    out: { type: 'string', default: 'crypto-node-benchmark.json' },
    runs: { type: 'string', default: '5' },
    quick: { type: 'boolean', default: false },
  },
})
const RUNS = Number(values.runs)
const BUDGET_MS = values.quick ? 60 : 400
const MIN_SAMPLES = values.quick ? 10 : 30
// Fast calls need many samples: at 400, a 1 µs call is measured over half a millisecond, and a
// single GC or JIT pause in that window moved its p95 from about 2.5 µs to 15 µs.
const MAX_SAMPLES = 20_000
// Shared CI runners add garbage-collection pauses and timer noise to the tail. p95 may exceed
// nodeCrypto's by up to 10%, plus 20 µs. The p95 check guards event-loop responsiveness, and a
// tail under 20 µs is far below any responsiveness concern; without it, a 36-byte blake3 call
// with a 2x better median and mean failed on occasional 15 µs runtime pauses. The mobile gate,
// measured on idle physical devices, requires p95 to be no worse; these runners are not idle.
const P95_RATIO = 1.1
const P95_SLACK_MS = 0.02

const pkg = (name) => join(root, 'packages', name, 'lib/index.js')
const { nobleCrypto } = await import(pkg('crypto'))
const { nodeCrypto } = await import(pkg('crypto-node'))
const { createNapiCrypto } = await import(pkg('crypto-napi'))
const { ed25519 } = await import(join(root, 'node_modules/@noble/curves/ed25519.js'))
const { p256 } = await import(join(root, 'node_modules/@noble/curves/nist.js'))

const napi = createNapiCrypto()
assert.equal(
  napi.backend,
  'napi',
  `crypto-napi did not load its binding: ${JSON.stringify(napi.failure)}`,
)

const bytes = (length, fill) => new Uint8Array(length).fill(fill)
const seed = bytes(32, 7)
const edKey = ed25519.getPublicKey(seed)
const esSecret = p256.utils.randomSecretKey()
const esKey = p256.getPublicKey(esSecret, true)

function cells() {
  const out = []
  // Shapes measured on the provider-integration branch: controller verifyBatch is nearly always one
  // item and at most 4, signing batches reach 17 (a reset or rotate signing set), and signed
  // messages run from about 140 B to 2.5 KiB (records, vault), with capability chains up to about
  // 12 KiB.
  const modes = [
    { mode: 'single', batch: 1 },
    { mode: 'batch', batch: 1 },
    { mode: 'batch', batch: 4 },
    { mode: 'batch', batch: 17 },
  ]
  for (const { mode, batch } of modes) {
    for (const size of [256, 1024, 2560, 12288]) {
      const message = bytes(size, 1)
      const edSignature = ed25519.sign(message, seed)
      const esSignature = p256.sign(message, esSecret, {
        lowS: true,
        prehash: true,
        format: 'compact',
      })
      const signItems = Array.from({ length: batch }, () => ({ privateKey: seed, message }))
      const edItems = Array.from({ length: batch }, () => ({
        alg: 'EdDSA',
        signature: edSignature,
        message,
        publicKey: edKey,
      }))
      const esItems = Array.from({ length: batch }, () => ({
        alg: 'ES256',
        signature: esSignature,
        message,
        publicKey: esKey,
      }))
      out.push(
        {
          op: 'ed25519-sign',
          mode,
          batch,
          size,
          run: (p) =>
            mode === 'single'
              ? p.sign({ alg: 'EdDSA', privateKey: seed, message })
              : p.signBatch({ alg: 'EdDSA', items: signItems }),
        },
        {
          op: 'ed25519-verify',
          mode,
          batch,
          size,
          run: (p) =>
            mode === 'single'
              ? p.verify({ alg: 'EdDSA', signature: edSignature, message, publicKey: edKey })
              : p.verifyBatch(edItems),
        },
        {
          op: 'es256-verify',
          mode,
          batch,
          size,
          // crypto-napi sends ES256 to nodeCrypto, single or batched, so there is nothing to gate.
          delegated: true,
          run: (p) =>
            mode === 'single'
              ? p.verify({ alg: 'ES256', signature: esSignature, message, publicKey: esKey })
              : p.verifyBatch(esItems),
        },
      )
    }
    // Records and vault hash single inputs: 36 B into 16-byte digests, and about 1-2.6 KiB into
    // 32-byte digests (store-vault alone makes about 60,000 such calls in its suite).
    for (const [size, dkLen] of [
      [36, 16],
      [1024, 32],
      [2600, 32],
      [65536, 32],
    ]) {
      const input = bytes(size, 2)
      const inputs = Array.from({ length: batch }, () => input)
      out.push({
        op: `blake3/${dkLen}`,
        mode,
        batch,
        size,
        run: (p) =>
          mode === 'single' ? p.blake3({ input, dkLen }) : p.blake3Batch({ inputs, dkLen }),
      })
    }
  }
  return out
}

function passesRule(t) {
  return t.napi.median <= t.node.median * 0.9 && t.napi.p95 <= t.node.p95 * P95_RATIO + P95_SLACK_MS
}

function percentileOf(values) {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.floor(sorted.length / 2)]
}

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)]
}

async function sample(fn, count) {
  const times = []
  for (let i = 0; i < count; i++) {
    const start = process.hrtime.bigint()
    await fn()
    times.push(Number(process.hrtime.bigint() - start) / 1e6)
  }
  times.sort((a, b) => a - b)
  return { median: percentile(times, 0.5), p95: percentile(times, 0.95), samples: count }
}

async function measure(cell, provider) {
  const fn = () => cell.run(provider)
  const start = performance.now()
  let warm = 0
  while (warm < 5 || performance.now() - start < BUDGET_MS / 10) {
    await fn()
    warm++
  }
  const estimate = (performance.now() - start) / warm
  const count = Math.max(MIN_SAMPLES, Math.min(MAX_SAMPLES, Math.round(BUDGET_MS / estimate)))
  return sample(fn, count)
}

const providers = { napi, node: nodeCrypto, noble: nobleCrypto }
const results = []
for (const cell of cells()) {
  const runs = []
  for (let run = 0; run < RUNS; run++) {
    // Rotate the order so warm caches and frequency scaling do not favour one provider.
    const order = ['napi', 'node', 'noble']
    for (let r = 0; r < run % 3; r++) order.push(order.shift())
    const timings = {}
    for (const name of order) {
      // Strict noble is context only; one run of it is enough.
      if (name === 'noble' && run > 0) continue
      timings[name] = await measure(cell, providers[name])
    }
    runs.push(timings)
  }
  const passes = runs.map(passesRule)
  const median = (name) => {
    const values = runs
      .filter((t) => t[name])
      .map((t) => t[name].median)
      .sort((a, b) => a - b)
    return values[Math.floor(values.length / 2)]
  }
  // A single outlier run on a shared runner should not flip a route: a cell passes when at least
  // RUNS - 1 runs pass and the median across runs also passes.
  const medianRun = {
    napi: { median: median('napi'), p95: percentileOf(runs.map((t) => t.napi.p95)) },
    node: { median: median('node'), p95: percentileOf(runs.map((t) => t.node.p95)) },
  }
  const passing = passes.filter(Boolean).length
  const status = cell.delegated
    ? 'delegated'
    : passing >= Math.max(1, RUNS - 1) && passesRule(medianRun)
      ? 'pass'
      : 'fail'
  const row = {
    op: cell.op,
    mode: cell.mode,
    batch: cell.batch,
    size: cell.size,
    status,
    passingRuns: passes.filter(Boolean).length,
    medianMs: { napi: median('napi'), node: median('node'), noble: median('noble') },
    runs,
  }
  results.push(row)
  console.log(
    `${status.padEnd(9)} ${cell.op.padEnd(15)} ${`${cell.mode}${cell.mode === 'batch' ? `x${cell.batch}` : ''}`.padEnd(8)} ${String(cell.size).padStart(5)} B  napi ${row.medianMs.napi.toFixed(4)} ms  node ${row.medianMs.node.toFixed(4)} ms  (${row.passingRuns}/${RUNS} runs)`,
  )
}

const failed = results.filter((row) => row.status === 'fail')
const report = {
  host: {
    platform: platform(),
    arch: arch(),
    cpu: cpus()[0]?.model,
    cpus: cpus().length,
    node: process.version,
  },
  runs: RUNS,
  rule: 'napi median <= 0.9 x nodeCrypto median and napi p95 <= 1.1 x nodeCrypto p95 + 20 µs, in at least runs - 1 runs and across the median run',
  status: failed.length === 0 ? 'proceed' : 'stop',
  failed: failed.map(
    (row) => `${row.op} ${row.mode}${row.mode === 'batch' ? `x${row.batch}` : ''} ${row.size}B`,
  ),
  results,
}
writeFileSync(values.out, `${JSON.stringify(report, null, 2)}\n`)
console.log(
  `\n${report.status}: ${results.length - failed.length}/${results.length} cells pass. Report: ${values.out}`,
)

if (process.env.GITHUB_STEP_SUMMARY) {
  const lines = [
    `### Node crypto gate on ${report.host.platform}-${report.host.arch}: ${report.status}`,
    '',
    `${report.host.cpu} (${report.host.cpus} CPUs), Node ${report.host.node}, ${RUNS} runs. Rule: ${report.rule}.`,
    '',
    '| Operation | Mode | Bytes | Status | napi ms | nodeCrypto ms | strict noble ms |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    ...results.map(
      (row) =>
        `| ${row.op} | ${row.mode}${row.mode === 'batch' ? ` ×${row.batch}` : ''} | ${row.size} | ${row.status} (${row.passingRuns}/${RUNS}) | ${row.medianMs.napi.toFixed(4)} | ${row.medianMs.node.toFixed(4)} | ${row.medianMs.noble.toFixed(4)} |`,
    ),
    '',
  ]
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.join('\n')}\n`)
}
process.exitCode = failed.length === 0 ? 0 : 1
