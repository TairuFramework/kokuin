import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

import { sourceFingerprint, stampArtifacts } from './crypto-artifacts.mjs'
import { ensureCryptoNative } from './ensure-crypto-native.mjs'

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'kokuin-ensure-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const write = (name, content = name) => {
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
    write(name)
  const buildFake = (platform) => {
    const prebuilt = 'packages/crypto-native/prebuilt'
    const libraries =
      platform === 'ios'
        ? [
            'ios/KokuinCrypto.xcframework/Info.plist',
            'ios/KokuinCrypto.xcframework/ios-arm64/libkokuin_crypto_ffi.a',
            'ios/KokuinCrypto.xcframework/ios-arm64_x86_64-simulator/libkokuin_crypto_ffi.a',
          ]
        : ['android/arm64-v8a/libkokuin_crypto_ffi.a', 'android/x86_64/libkokuin_crypto_ffi.a']
    for (const library of libraries) write(`${prebuilt}/${library}`)
    stampArtifacts(root, platform, sourceFingerprint(root))
  }
  return { root, write, buildFake }
}

test('builds every platform when no artifacts exist', (t) => {
  const { root, buildFake } = fixture(t)
  const built = []
  ensureCryptoNative(root, (platform) => {
    built.push(platform)
    buildFake(platform)
  })
  assert.deepEqual(built, ['ios', 'android'])
})

test('builds nothing when artifacts are current', (t) => {
  const { root, buildFake } = fixture(t)
  buildFake('ios')
  buildFake('android')
  ensureCryptoNative(root, (platform) => assert.fail(`unexpected ${platform} build`))
})

test('rebuilds only the platform whose artifacts were altered', (t) => {
  const { root, write, buildFake } = fixture(t)
  buildFake('ios')
  buildFake('android')
  write('packages/crypto-native/prebuilt/android/x86_64/libkokuin_crypto_ffi.a', 'altered')
  const built = []
  ensureCryptoNative(root, (platform) => {
    built.push(platform)
    buildFake(platform)
  })
  assert.deepEqual(built, ['android'])
})

test('rebuilds every platform when crypto sources change', (t) => {
  const { root, write, buildFake } = fixture(t)
  buildFake('ios')
  buildFake('android')
  write('crates/core/src/lib.rs', 'changed')
  const built = []
  ensureCryptoNative(root, (platform) => {
    built.push(platform)
    buildFake(platform)
  })
  assert.deepEqual(built, ['ios', 'android'])
})

test('fails when a build leaves artifacts stale', (t) => {
  const { root } = fixture(t)
  assert.throws(() => ensureCryptoNative(root, () => {}), /ios crypto binaries are still stale/)
})
