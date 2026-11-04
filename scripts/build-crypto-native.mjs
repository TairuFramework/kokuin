import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { sourceFingerprint, stampArtifacts } from './crypto-artifacts.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const prebuilt = join(root, 'packages/crypto-native/prebuilt')
const targetDirectory = resolve(root, process.env.CARGO_TARGET_DIR || 'target')
const platform = process.argv[2]
if (platform !== 'ios' && platform !== 'android')
  throw new Error('Usage: node scripts/build-crypto-native.mjs ios|android')
const fingerprint = sourceFingerprint(root)

function run(command, args, env = {}) {
  execFileSync(command, args, { cwd: root, stdio: 'inherit', env: { ...process.env, ...env } })
}

function build(target, env = {}) {
  run(
    'pnpm',
    [
      'exec',
      'cargo',
      'build',
      '-p',
      'kokuin-crypto-ffi',
      '--release',
      '--locked',
      '--offline',
      '--target',
      target,
    ],
    env,
  )
  return join(targetDirectory, target, 'release/libkokuin_crypto_ffi.a')
}

if (platform === 'ios') {
  const env = { IPHONEOS_DEPLOYMENT_TARGET: '16.4' }
  const device = build('aarch64-apple-ios', env)
  const armSimulator = build('aarch64-apple-ios-sim', env)
  const intelSimulator = build('x86_64-apple-ios', env)
  const simulator = join(prebuilt, 'ios/simulator/libkokuin_crypto_ffi.a')
  mkdirSync(dirname(simulator), { recursive: true })
  run('xcrun', ['lipo', '-create', armSimulator, intelSimulator, '-output', simulator])
  const output = join(prebuilt, 'ios/KokuinCrypto.xcframework')
  if (existsSync(output)) rmSync(output, { recursive: true })
  const headers = join(root, 'packages/crypto-native/cpp/generated')
  run('xcodebuild', [
    '-create-xcframework',
    '-library',
    device,
    '-headers',
    headers,
    '-library',
    simulator,
    '-headers',
    headers,
    '-output',
    output,
  ])
} else {
  const sdk =
    process.env.ANDROID_HOME ??
    join(homedir(), process.platform === 'darwin' ? 'Library/Android/sdk' : 'Android/Sdk')
  const ndk = process.env.KOKUIN_ANDROID_NDK ?? join(sdk, 'ndk/27.1.12297006')
  const host =
    process.platform === 'darwin'
      ? 'darwin-x86_64'
      : process.platform === 'linux'
        ? 'linux-x86_64'
        : null
  if (host === null) throw new Error('Android cross-builds require macOS or Linux')
  const bin = join(ndk, 'toolchains/llvm/prebuilt', host, 'bin')
  for (const [target, abi, compiler] of [
    ['aarch64-linux-android', 'arm64-v8a', 'aarch64-linux-android24-clang'],
    ['x86_64-linux-android', 'x86_64', 'x86_64-linux-android24-clang'],
  ]) {
    const linker = join(bin, compiler)
    if (!existsSync(linker)) throw new Error(`Missing NDK compiler: ${linker}`)
    const targetVariable = target.replaceAll('-', '_')
    const library = build(target, {
      [`CC_${targetVariable}`]: linker,
      [`AR_${targetVariable}`]: join(bin, 'llvm-ar'),
      [`CARGO_TARGET_${targetVariable.toUpperCase()}_LINKER`]: linker,
    })
    const output = join(prebuilt, 'android', abi)
    mkdirSync(output, { recursive: true })
    cpSync(library, join(output, 'libkokuin_crypto_ffi.a'))
  }
}

stampArtifacts(root, platform, fingerprint)
