import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

import { checkCryptoPackage } from './check-crypto-package.mjs'
import { sourceFingerprint, stampArtifacts } from './crypto-artifacts.mjs'

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'kokuin-package-'))
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
  for (const name of [
    'lib/index.js',
    'lib/index.d.ts',
    'LICENSE',
    'prebuilt/THIRD_PARTY_LICENSES.txt',
    'cpp/HybridCrypto.hpp',
    'cpp/HybridCrypto.cpp',
    'cpp/OwnedBytes.hpp',
    'cpp/CryptoWorker.hpp',
    'cpp/generated/kokuin_crypto.h',
    'KokuinCrypto.podspec',
    'react-native.config.js',
    'nitrogen/generated/shared/c++/HybridCryptoSpec.hpp',
    'nitrogen/generated/shared/c++/HybridCryptoSpec.cpp',
    'nitrogen/generated/ios/KokuinCrypto+autolinking.rb',
    'nitrogen/generated/ios/KokuinCryptoAutolinking.mm',
    'nitrogen/generated/android/KokuinCrypto+autolinking.cmake',
    'nitrogen/generated/android/KokuinCrypto+autolinking.gradle',
    'nitrogen/generated/android/KokuinCryptoOnLoad.cpp',
    'android/build.gradle',
    'android/CMakeLists.txt',
    'android/cpp-adapter.cpp',
    'android/src/main/AndroidManifest.xml',
    'android/src/main/java/com/kokuin/crypto/CryptoPackage.kt',
    'prebuilt/ios/KokuinCrypto.xcframework/Info.plist',
    'prebuilt/ios/KokuinCrypto.xcframework/ios-arm64/libkokuin_crypto_ffi.a',
    'prebuilt/ios/KokuinCrypto.xcframework/ios-arm64_x86_64-simulator/libkokuin_crypto_ffi.a',
    'prebuilt/android/arm64-v8a/libkokuin_crypto_ffi.a',
    'prebuilt/android/x86_64/libkokuin_crypto_ffi.a',
  ])
    write(`packages/crypto-native/${name}`)
  write(
    'packages/crypto-native/package.json',
    JSON.stringify({
      name: '@kokuin/crypto-native',
      version: '0.1.0',
      publishConfig: { access: 'public' },
    }),
  )
  for (const platform of ['ios', 'android']) stampArtifacts(root, platform, sourceFingerprint(root))
  return { root, write }
}

test('accepts a complete package with matching binaries', (t) => {
  const { root } = fixture(t)
  assert.doesNotThrow(() => checkCryptoPackage(root))
})

test('rejects stale or altered native libraries before distribution', (t) => {
  const { root, write } = fixture(t)
  write('packages/crypto-native/prebuilt/android/x86_64/libkokuin_crypto_ffi.a', 'altered')
  assert.throws(() => checkCryptoPackage(root), /android/i)
})

test('rejects missing generated glue and licence notices', (t) => {
  const { root } = fixture(t)
  rmSync(join(root, 'packages/crypto-native/prebuilt/THIRD_PARTY_LICENSES.txt'))
  assert.throws(() => checkCryptoPackage(root), /THIRD_PARTY_LICENSES/)
})

test('rejects missing platform registration files', (t) => {
  const { root } = fixture(t)
  rmSync(join(root, 'packages/crypto-native/nitrogen/generated/android/KokuinCryptoOnLoad.cpp'))
  assert.throws(() => checkCryptoPackage(root), /KokuinCryptoOnLoad/)
})
