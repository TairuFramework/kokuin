import assert from 'node:assert/strict'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { ensureCryptoNapi } from './ensure-crypto-napi.mjs'

const TARGET = 'darwin-arm64'
const MAIN = `kokuin-crypto-napi.${TARGET}.node`

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'kokuin-ensure-napi-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const directory = join(root, TARGET)
  mkdirSync(directory)
  writeFileSync(join(directory, 'package.json'), JSON.stringify({ main: MAIN }))
  return directory
}

function fakeRun({ runs = [{ databaseId: 7 }], artifact = true, attested = true } = {}) {
  const calls = []
  const run = (command, args) => {
    calls.push([command, ...args].join(' '))
    if (command === 'git') return 'abc123\n'
    if (args[1] === 'list') return JSON.stringify(runs)
    if (args[1] === 'download') {
      if (!artifact) throw new Error('no artifact')
      writeFileSync(join(args[args.indexOf('--dir') + 1], MAIN), 'attested')
    }
    if (args[0] === 'attestation' && !attested) throw new Error('Verification failed')
    return ''
  }
  return { calls, run }
}

test('puts the attested binary of this commit into the package', (t) => {
  const directory = fixture(t)
  const { calls, run } = fakeRun()
  ensureCryptoNapi(directory, run)
  assert.equal(readFileSync(join(directory, MAIN), 'utf8'), 'attested')
  assert.match(calls[1], /--commit abc123 --status success/)
  assert.match(calls[2], new RegExp(`run download 7 .*--name crypto-napi-${TARGET} `))
  assert.match(calls[3], /attestation verify/)
})

test('replaces a binary left by an earlier release', (t) => {
  const directory = fixture(t)
  writeFileSync(join(directory, MAIN), 'stale')
  ensureCryptoNapi(directory, fakeRun().run)
  assert.equal(readFileSync(join(directory, MAIN), 'utf8'), 'attested')
})

test('stops without a successful run for this commit', (t) => {
  const directory = fixture(t)
  const { run } = fakeRun({ runs: [] })
  assert.throws(() => ensureCryptoNapi(directory, run), /No successful .* run for abc123/)
  assert.equal(existsSync(join(directory, MAIN)), false)
})

test('stops when the run has no binary for this target', (t) => {
  const directory = fixture(t)
  const { run } = fakeRun({ artifact: false })
  assert.throws(() => ensureCryptoNapi(directory, run), /no artifact/)
  assert.equal(existsSync(join(directory, MAIN)), false)
})

test('keeps an unverified binary out of the package', (t) => {
  const directory = fixture(t)
  const { run } = fakeRun({ attested: false })
  assert.throws(() => ensureCryptoNapi(directory, run), /Verification failed/)
  assert.equal(existsSync(join(directory, MAIN)), false)
})

test('every platform package fetches its binary before publishing', () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  const packages = join(root, 'packages/crypto-napi/npm')
  const targets = readdirSync(packages)
  assert.equal(targets.length, 8)
  for (const target of targets) {
    const manifest = JSON.parse(readFileSync(join(packages, target, 'package.json'), 'utf8'))
    assert.equal(
      manifest.scripts?.prepublishOnly,
      'node ../../../../scripts/ensure-crypto-napi.mjs',
      target,
    )
  }
})
