import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

export type GoldenCase = { name: string; input: unknown; expected: unknown }

export function checkGolden(path: string, cases: Array<GoldenCase>): void {
  assert.equal(new Set(cases.map(({ name }) => name)).size, cases.length, 'Duplicate case names')
  if (process.env.UPDATE_GOLDEN === '1') {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, `${JSON.stringify({ version: 1, cases }, null, 2)}\n`)
    return
  }
  const golden = JSON.parse(readFileSync(path, 'utf8')) as {
    version: number
    cases: Array<GoldenCase>
  }
  assert.equal(golden.version, 1, 'Unsupported golden version')
  assert.deepEqual(
    golden.cases.map(({ name }) => name).sort(),
    cases.map(({ name }) => name).sort(),
    'Golden case names differ',
  )
  const saved = new Map(golden.cases.map((entry) => [entry.name, entry]))
  for (const entry of cases) {
    assert.deepEqual(entry, saved.get(entry.name), `Golden case: ${entry.name}`)
  }
}
