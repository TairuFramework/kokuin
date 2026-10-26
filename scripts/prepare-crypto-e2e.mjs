import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { artifactsCurrent } from './crypto-artifacts.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const platform = process.argv[2]
if (platform !== 'ios' && platform !== 'android') throw new Error('Expected ios or android')
if (artifactsCurrent(root, platform)) {
  console.log(`Using prebuilt ${platform} crypto libraries`)
} else {
  const run = (command, args) => execFileSync(command, args, { cwd: root, stdio: 'inherit' })
  const targets =
    platform === 'ios'
      ? ['aarch64-apple-ios', 'aarch64-apple-ios-sim', 'x86_64-apple-ios']
      : ['aarch64-linux-android', 'x86_64-linux-android']
  run('rustup', ['target', 'add', '--toolchain', '1.99.1', ...targets])
  if (platform === 'android' && !process.env.KOKUIN_ANDROID_NDK) {
    const sdk =
      process.env.ANDROID_HOME ??
      join(homedir(), process.platform === 'darwin' ? 'Library/Android/sdk' : 'Android/Sdk')
    if (!existsSync(join(sdk, 'ndk/27.1.12297006'))) {
      run(join(sdk, 'cmdline-tools/latest/bin/sdkmanager'), ['ndk;27.1.12297006'])
    }
  }
  run(process.execPath, [join(root, 'scripts/build-crypto-native.mjs'), platform])
}
