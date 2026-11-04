import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { collectNotices } from './crypto-notices.mjs'

test('retains complete upstream licence and notice text', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'kokuin-notices-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  mkdirSync(join(root, 'crate'))
  writeFileSync(join(root, 'crate/LICENSE-MIT'), 'Complete upstream licence text')
  writeFileSync(join(root, 'crate/NOTICE'), 'Upstream attribution')
  const result = collectNotices([
    {
      name: 'example',
      version: '1.0.0',
      license: 'MIT',
      manifest_path: join(root, 'crate/Cargo.toml'),
    },
  ])
  assert.match(result, /example 1.0.0/)
  assert.match(result, /Complete upstream licence text/)
  assert.match(result, /Upstream attribution/)
})

test('rejects a dependency without licence files', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'kokuin-notices-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  assert.throws(
    () =>
      collectNotices([
        {
          name: 'missing',
          version: '1.0.0',
          license: 'MIT',
          manifest_path: join(root, 'Cargo.toml'),
        },
      ]),
    /missing/,
  )
})

test('includes pinned upstream notices when an npm package omits its licence', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'kokuin-notices-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  writeFileSync(join(root, 'LICENSE'), 'Pinned upstream licence text')
  const result = collectNotices([
    { name: 'native-peer', version: '1.0.0', license: 'MIT', licenseDirectory: root },
  ])
  assert.match(result, /Pinned upstream licence text/)
})
