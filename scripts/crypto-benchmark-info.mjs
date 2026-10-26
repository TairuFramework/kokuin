import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { artifactsCurrent, sourceFingerprint } from './crypto-artifacts.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const run = (command, args) => execFileSync(command, args, { cwd: root, encoding: 'utf8' }).trim()
const version = (name) =>
  JSON.parse(readFileSync(join(root, 'node_modules', name, 'package.json'), 'utf8')).version
const toolchain = readFileSync(join(root, 'Cargo.toml'), 'utf8')

console.log(
  JSON.stringify(
    {
      revision: run('git', ['rev-parse', 'HEAD']),
      dirty: run('git', ['status', '--porcelain']).length !== 0,
      cryptoSourceFingerprint: sourceFingerprint(root),
      matchingNativeArtifacts: {
        ios: artifactsCurrent(root, 'ios'),
        android: artifactsCurrent(root, 'android'),
      },
      rustc: run('rustc', ['--version']),
      xcode: process.platform === 'darwin' ? run('xcodebuild', ['-version']) : null,
      pnpm: run('pnpm', ['--version']),
      packages: Object.fromEntries(
        [
          '@noble/curves',
          '@noble/hashes',
          'react-native-nitro-modules',
          'react-native',
          'expo',
        ].map((name) => [name, version(name)]),
      ),
      cargoManifest: toolchain,
      nativeBuild: {
        profile: 'release',
        lto: 'thin',
        codegenUnits: 1,
        iosMinimum: '16.4',
        androidLibraryAPI: 24,
        androidNDK: '27.1.12297006',
      },
      transport:
        'Array of buffer views, synchronously copied before a single worker dispatch per batch',
    },
    null,
    2,
  ),
)
