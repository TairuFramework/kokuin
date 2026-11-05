import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { ensureCryptoNapi } from './ensure-crypto-napi.mjs'

const TARGETS = ['darwin-arm64', 'win32-x64']

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'kokuin-ensure-napi-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  for (const target of TARGETS) {
    const directory = join(root, 'packages', `crypto-napi-${target}`)
    mkdirSync(directory, { recursive: true })
    writeFileSync(
      join(directory, 'package.json'),
      JSON.stringify({ name: `@kokuin/crypto-napi-${target}`, version: '1.0.0' }),
    )
  }
  return root
}

function fakeRun({ published = [], runs = [{ databaseId: 7 }], artifact = true, attested = true }) {
  const calls = []
  const run = (command, args) => {
    calls.push([command, ...args].join(' '))
    if (command === 'npm') {
      if (published.some((target) => args[1].includes(target))) return '1.0.0\n'
      throw new Error('E404')
    }
    if (command === 'git') return 'abc123\n'
    if (args[0] === 'run' && args[1] === 'list') return JSON.stringify(runs)
    if (args[0] === 'run' && args[1] === 'download') {
      const target = args[args.indexOf('--name') + 1].slice('crypto-napi-'.length)
      if (artifact) {
        writeFileSync(
          join(args[args.indexOf('--dir') + 1], `kokuin-crypto-napi.${target}.node`),
          '',
        )
      }
      return ''
    }
    if (args[0] === 'attestation' && !attested) throw new Error('Verification failed')
    return ''
  }
  return { calls, run }
}

test('does nothing when every platform package is published', (t) => {
  const { calls, run } = fakeRun({ published: TARGETS })
  assert.equal(ensureCryptoNapi(fixture(t), run), false)
  assert.equal(calls.filter((call) => call.startsWith('gh ')).length, 0)
})

test('fetches and verifies every binary when one package is unpublished', (t) => {
  const { calls, run } = fakeRun({ published: [TARGETS[0]] })
  assert.equal(ensureCryptoNapi(fixture(t), run), true)
  assert.match(
    calls.find((call) => call.includes('run list')),
    /--commit abc123 --status success/,
  )
  assert.equal(calls.filter((call) => call.includes('run download 7')).length, 2)
  assert.equal(calls.filter((call) => call.includes('attestation verify')).length, 2)
})

test('stops without a successful run for this commit', (t) => {
  const { run } = fakeRun({ runs: [] })
  assert.throws(() => ensureCryptoNapi(fixture(t), run), /No successful .* run for abc123/)
})

test('stops when an artifact lacks its binary', (t) => {
  const { run } = fakeRun({ artifact: false })
  assert.throws(() => ensureCryptoNapi(fixture(t), run), /did not contain/)
})

test('stops when an attestation does not verify', (t) => {
  const { run } = fakeRun({ attested: false })
  assert.throws(() => ensureCryptoNapi(fixture(t), run), /Verification failed/)
})
