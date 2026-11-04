import { readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { artifactsCurrent } from './crypto-artifacts.mjs'

export const nativePackageFiles = [
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
  'lib/provider.js',
  'lib/provider.d.ts',
  'lib/Crypto.nitro.js',
  'lib/Crypto.nitro.d.ts',
  'nitrogen/generated/shared/c++/CryptoRequest.hpp',
  'nitrogen/generated/shared/c++/ByteView.hpp',
  'nitrogen/generated/android/KokuinCryptoOnLoad.hpp',
  'nitrogen/generated/android/kotlin/com/margelo/nitro/kokuin/crypto/KokuinCryptoOnLoad.kt',
  'nitrogen/generated/ios/KokuinCrypto-Swift-Cxx-Bridge.cpp',
  'nitrogen/generated/ios/KokuinCrypto-Swift-Cxx-Bridge.hpp',
  'nitrogen/generated/ios/KokuinCrypto-Swift-Cxx-Umbrella.hpp',
  'nitrogen/generated/ios/KokuinCryptoAutolinking.swift',
  'prebuilt/ios/KokuinCrypto.xcframework/Info.plist',
  'prebuilt/ios/KokuinCrypto.xcframework/ios-arm64/libkokuin_crypto_ffi.a',
  'prebuilt/ios/KokuinCrypto.xcframework/ios-arm64_x86_64-simulator/libkokuin_crypto_ffi.a',
  'prebuilt/android/arm64-v8a/libkokuin_crypto_ffi.a',
  'prebuilt/android/x86_64/libkokuin_crypto_ffi.a',
]

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
  for (const name of nativePackageFiles) {
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
