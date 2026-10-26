import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

import { artifactsCurrent, sourceFingerprint, stampArtifacts } from './crypto-artifacts.mjs'

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'kokuin-artifacts-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const write = (name, content) => {
    const path = join(root, name)
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, content)
  }
  for (const name of [
    'Cargo.toml',
    'Cargo.lock',
    'rust-toolchain.toml',
    'crates/core/src/lib.rs',
    'scripts/build-crypto-native.mjs',
    'scripts/crypto-artifacts.mjs',
  ])
    write(name, name)
  for (const abi of ['arm64-v8a', 'x86_64'])
    write(`packages/crypto-native/prebuilt/android/${abi}/libkokuin_crypto_ffi.a`, abi)
  return { root, write }
}

test('reuses matching binaries but rejects changed Rust sources and build recipes', (t) => {
  const { root, write } = fixture(t)
  assert.equal(artifactsCurrent(root, 'android'), false)
  stampArtifacts(root, 'android', sourceFingerprint(root))
  assert.equal(artifactsCurrent(root, 'android'), true)
  write('crates/core/src/lib.rs', 'changed crypto operation')
  assert.equal(artifactsCurrent(root, 'android'), false)
  stampArtifacts(root, 'android', sourceFingerprint(root))
  assert.equal(artifactsCurrent(root, 'android'), true)
  write('scripts/build-crypto-native.mjs', 'changed compiler flags')
  assert.equal(artifactsCurrent(root, 'android'), false)
})

test('rejects modified or missing binaries and source changes during compilation', (t) => {
  const { root, write } = fixture(t)
  const fingerprint = sourceFingerprint(root)
  stampArtifacts(root, 'android', fingerprint)
  write('packages/crypto-native/prebuilt/android/x86_64/libkokuin_crypto_ffi.a', 'stale binary')
  assert.equal(artifactsCurrent(root, 'android'), false)
  stampArtifacts(root, 'android', fingerprint)
  rmSync(join(root, 'packages/crypto-native/prebuilt/android/arm64-v8a/libkokuin_crypto_ffi.a'))
  assert.equal(artifactsCurrent(root, 'android'), false)
  write('Cargo.lock', 'changed dependency')
  assert.throws(() => stampArtifacts(root, 'android', fingerprint), /sources changed/)
})
