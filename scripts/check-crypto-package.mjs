import { readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { artifactsCurrent } from './crypto-artifacts.mjs'

export function checkCryptoPackage(root) {
  const directory = join(root, 'packages/crypto-native')
  const manifest = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'))
  if (manifest.private || manifest.publishConfig?.access !== 'public') {
    throw new Error('Native crypto package is not configured for public distribution')
  }
  for (const platform of ['ios', 'android']) {
    if (!artifactsCurrent(root, platform)) {
      throw new Error(`Missing or stale ${platform} crypto binaries. Rebuild before packing.`)
    }
  }
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
  ]) {
    const path = join(directory, name)
    try {
      if (!statSync(path).isFile() || statSync(path).size === 0) throw new Error('empty')
    } catch (cause) {
      throw new Error(`Missing package file: ${name}`, { cause })
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  checkCryptoPackage(resolve(dirname(fileURLToPath(import.meta.url)), '..'))
  console.log('Native crypto package inputs are complete and current')
}
