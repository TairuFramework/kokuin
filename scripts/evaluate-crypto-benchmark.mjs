import { readFileSync } from 'node:fs'

import { evaluateGate } from '../tests/e2e-expo/crypto/gate.ts'

const files = process.argv.slice(2)
if (files.length === 0)
  throw new Error('Usage: node scripts/evaluate-crypto-benchmark.mjs ios.json android.json')
const samples = files.flatMap((file) => {
  const value = JSON.parse(readFileSync(file, 'utf8'))
  if (value === null || typeof value !== 'object' || !Array.isArray(value.samples)) {
    throw new TypeError(`Expected a benchmark export with a samples array: ${file}`)
  }
  return value.samples
})
console.log(JSON.stringify(evaluateGate(samples), null, 2))
